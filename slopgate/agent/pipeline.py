"""Orchestration, staged so the changelog can be measured on identical inputs.

The pipeline runs at a named STAGE. Each stage switches on one more capability,
matching one Improvement Changelog row, so the harness can measure the exact
delta each design choice contributes on the same cases:

    baseline  single prompt, verdict from report text alone, NO tools
    tool      triage authors + runs a PoC; verdict from the agent (no gate)
    gate      + deterministic execution-fidelity gate
    abstain   + explicit abstention when no decisive test was possible
    verify    + independent per-claim verifier
    challenge + adversarial challenger (the full system)

Every stage returns a TriageMemo carrying its own cost/latency accounting.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from slopgate.agent.challenge import challenge_confirmation
from slopgate.agent.gate import apply_fidelity_gate
from slopgate.agent.threat_model import apply_threat_model_gate
from slopgate.agent.llm import ask_json
from slopgate.agent.schema import Claim, ReproEvidence, Report, TriageMemo, Verdict
from slopgate.agent.triage import run_triage, SYSTEM as TRIAGE_SYSTEM
from slopgate.agent.verify import verify_claims
from slopgate.model.gemini import GenResult, PRICE_PER_MTOK_INPUT, PRICE_PER_MTOK_OUTPUT
from slopgate.model.trace import Trajectory

STAGES = ["baseline", "tool", "gate", "abstain", "verify", "challenge"]

# Outcomes that mean "we could not run a decisive test" -> honest abstention.
_INDECISIVE = {"ERRORED", "INCONCLUSIVE", "TIMEOUT", "AMBIGUOUS", "ENV_MISSING",
               "HOST_TIMEOUT", "HARNESS_ERROR", "NO_POC"}

_BASELINE_SYSTEM = (
    "You are a security triage engineer. Read the vulnerability report and decide "
    "whether it is a real, exploitable vulnerability. Respond with your best "
    "judgement based on the report."
)


def _finalize(memo: TriageMemo, trajectory: Trajectory) -> TriageMemo:
    memo.llm_calls = trajectory.llm_calls
    memo.total_tokens = trajectory.total_prompt_tokens + trajectory.total_output_tokens
    memo.est_cost_usd = (
        trajectory.total_prompt_tokens / 1_000_000 * PRICE_PER_MTOK_INPUT
        + trajectory.total_output_tokens / 1_000_000 * PRICE_PER_MTOK_OUTPUT
    )
    memo.wall_latency_s = trajectory.wall_latency_s
    return memo


def _baseline(report: Report, trajectory: Trajectory) -> TriageMemo:
    """The fair baseline: one prompt, no tools. What a swamped maintainer does."""
    prompt = (
        f"Vulnerability report for {report.package} {report.affected_version}:\n\n"
        f"Title: {report.title}\n\n{report.body}\n\n"
        "Return JSON: {\"verdict\": \"confirmed\"|\"not_reproducible\"|"
        "\"insufficient_evidence\", \"summary\": \"2-4 sentences\"}."
    )
    data, _ = ask_json(trajectory, agent="baseline", system=_BASELINE_SYSTEM, prompt=prompt)
    data = data or {}
    verdict = Verdict.coerce(data.get("verdict", "insufficient_evidence"))
    summary = str(data.get("summary", "")).strip() or "No summary produced."
    memo = TriageMemo(report_id=report.report_id, package=report.package,
                      affected_version=report.affected_version, verdict=verdict,
                      summary=summary)
    return _finalize(memo, trajectory)


def run_pipeline(report: Report, stage: str, trajectory: Trajectory) -> TriageMemo:
    if stage not in STAGES:
        raise ValueError(f"unknown stage {stage!r}; expected one of {STAGES}")
    if stage == "baseline":
        return _baseline(report, trajectory)

    draft = run_triage(report, trajectory)
    verdict = draft.proposed_verdict
    abstentions: list[str] = []
    claims_obj: list[Claim] = [Claim(text=c) for c in draft.claims]
    challenger_note = ""

    # gate (and every stage above it) applies the deterministic fidelity gate
    if stage in ("gate", "abstain", "verify", "challenge"):
        gated = apply_fidelity_gate(verdict, trajectory)
        verdict = gated.verdict
        if gated.downgraded:
            abstentions.append(gated.reason)

    # abstain: when no decisive test ran, prefer honest abstention over a guess
    if stage in ("abstain", "verify", "challenge"):
        if draft.repro_outcome in _INDECISIVE and verdict != Verdict.CONFIRMED:
            if verdict != Verdict.INSUFFICIENT:
                trajectory.note(agent="abstain",
                                message="no decisive reproduction; abstaining for human review",
                                data={"outcome": draft.repro_outcome})
            verdict = Verdict.INSUFFICIENT
            abstentions.append(
                f"No decisive reproduction was possible (outcome: {draft.repro_outcome}); "
                "a human should confirm the affected version and re-test."
            )

    # verify: independent per-claim check
    if stage in ("verify", "challenge"):
        claims_obj = verify_claims(report, draft.claims, draft.repro_outcome or "",
                                   draft.repro_stdout, trajectory) or claims_obj

    # challenge: adversarially stress any surviving confirmation (see the note in
    # evaluate_all_stages: executable proof is not overturned by rhetoric).
    if stage == "challenge" and verdict == Verdict.CONFIRMED:
        outcome = challenge_confirmation(
            report, draft.summary, draft.repro_outcome or "", draft.repro_stdout,
            draft.repro_command, trajectory)
        challenger_note = outcome.note
        if outcome.revised:
            if trajectory.has_reproduced_artifact():
                abstentions.append(
                    "Adversarial reviewer raised an objection; confirmation is backed "
                    "by an observed reproduction, so it stands pending human review.")
            else:
                verdict = outcome.verdict
                abstentions.append("Confirmation revised down after adversarial review.")

    # synthesized-PoC strict re-verify: a self-authored PoC (no reporter PoC) must
    # actually demonstrate the claimed impact, not merely print the success marker.
    if stage == "challenge" and verdict == Verdict.CONFIRMED and draft.poc_synthesized:
        from slopgate.agent.synthesize import demonstrates_claim
        if not demonstrates_claim(report, draft.poc_used or "", draft.repro_outcome or "",
                                  draft.repro_stdout, trajectory):
            verdict = Verdict.INSUFFICIENT
            abstentions.append(
                "The reproduction used an agent-synthesized PoC that did not clearly "
                "demonstrate the claimed impact; a human should verify the finding.")

    # threat-model gate: a reproduction that requires an attacker-controlled
    # trusted resource is trust-model confusion, not a vulnerability.
    if stage == "challenge" and verdict == Verdict.CONFIRMED:
        tm = apply_threat_model_gate(report, verdict, draft.repro_outcome or "",
                                     draft.repro_stdout, trajectory)
        verdict = tm.verdict
        if tm.note:
            abstentions.append(tm.note)

    reproduction = None
    if draft.env_id:
        reproduction = ReproEvidence(
            env_id=draft.env_id, outcome=draft.repro_outcome or "NO_POC",
            reproduced=draft.reproduced, command=draft.repro_command,
            stdout_tail=draft.repro_stdout[-2000:], poc=draft.poc_used or "",
        )

    if draft.sweep_hit_env and stage in ("abstain", "verify", "challenge"):
        abstentions.append(
            f"The submitted proof-of-concept does NOT reproduce on the claimed "
            f"{report.package} {report.affected_version}, but the same PoC DOES "
            f"reproduce on `{draft.sweep_hit_env}`. The underlying vulnerability is "
            f"real on that version; confirm the intended version range before closing."
        )

    memo = TriageMemo(
        report_id=report.report_id, package=report.package,
        affected_version=report.affected_version, verdict=verdict,
        summary=draft.summary, claims=claims_obj, reproduction=reproduction,
        abstentions=abstentions, challenger_note=challenger_note,
    )
    return _finalize(memo, trajectory)


def evaluate_all_stages(report: Report, trajectory: Trajectory) -> dict[str, TriageMemo]:
    """Produce a memo for EVERY changelog stage from a single triage execution.

    Running each stage as a separate pipeline would re-pay for the triage LLM
    calls six times and, worse, let model nondeterminism vary the input across
    stages. Instead we run the substantive work once and derive each stage's
    verdict from the same draft -- so the changelog compares stages on identical
    inputs, and the cost per case is ~half.
    """
    out: dict[str, TriageMemo] = {}

    def snapshot(memo: TriageMemo) -> TriageMemo:
        return _finalize(memo, trajectory)

    # --- baseline: independent, tool-free path ---
    out["baseline"] = _baseline(report, trajectory)

    # --- one real triage execution (claims + PoC + reproduction + proposed verdict) ---
    draft = run_triage(report, trajectory)
    reproduction = None
    if draft.env_id:
        reproduction = ReproEvidence(
            env_id=draft.env_id, outcome=draft.repro_outcome or "NO_POC",
            reproduced=draft.reproduced, command=draft.repro_command,
            stdout_tail=draft.repro_stdout[-2000:], poc=draft.poc_used or "",
        )

    # Diagnostic from the version sweep, added to every memo from `abstain` on so
    # a maintainer sees a real-but-misversioned gadget for what it is. It does not
    # flip the verdict: evidence cannot separate an honest version mistake from
    # careless slop, so the call is surfaced to the human, not made for them.
    sweep_note = (
        f"The submitted proof-of-concept does NOT reproduce on the claimed "
        f"{report.package} {report.affected_version}, but the same PoC DOES "
        f"reproduce on `{draft.sweep_hit_env}`. The underlying vulnerability is "
        f"real on that version; confirm the intended version range before closing."
        if draft.sweep_hit_env else None
    )

    def base_memo(verdict: Verdict, claims, abstentions, challenger_note="",
                  with_sweep: bool = False) -> TriageMemo:
        abst = list(abstentions)
        if with_sweep and sweep_note:
            abst.append(sweep_note)
        return TriageMemo(
            report_id=report.report_id, package=report.package,
            affected_version=report.affected_version, verdict=verdict,
            summary=draft.summary, claims=list(claims), reproduction=reproduction,
            abstentions=abst, challenger_note=challenger_note,
        )

    plain_claims = [Claim(text=c) for c in draft.claims]

    # tool: agent's proposed verdict, no gate
    out["tool"] = snapshot(base_memo(draft.proposed_verdict, plain_claims, []))

    # gate: deterministic downgrade of unbacked confirmations
    gated = apply_fidelity_gate(draft.proposed_verdict, trajectory)
    gate_abstentions = [gated.reason] if gated.downgraded else []
    out["gate"] = snapshot(base_memo(gated.verdict, plain_claims, gate_abstentions))

    # abstain: honest abstention when no decisive test ran
    verdict = gated.verdict
    abstentions = list(gate_abstentions)
    if draft.repro_outcome in _INDECISIVE and verdict != Verdict.CONFIRMED:
        verdict = Verdict.INSUFFICIENT
        abstentions.append(
            f"No decisive reproduction was possible (outcome: {draft.repro_outcome}); "
            "a human should confirm the affected version and re-test."
        )
    out["abstain"] = snapshot(base_memo(verdict, plain_claims, abstentions, with_sweep=True))

    # verify: independent per-claim check (annotates claims; may flag unsupported)
    verified_claims = verify_claims(report, draft.claims, draft.repro_outcome or "",
                                    draft.repro_stdout, trajectory) or plain_claims
    out["verify"] = snapshot(base_memo(verdict, verified_claims, abstentions, with_sweep=True))

    # challenge: adversarially stress a surviving confirmation.
    # Design decision (see CHANGELOG): a confirmation at this point is backed by a
    # real REPRODUCED artifact (the gate guarantees it). We do NOT let an LLM's
    # rhetorical objection overturn executable proof -- an earlier version that
    # could flip the verdict over-rejected genuine vulnerabilities. Instead the
    # challenger's dissent is recorded and the case is flagged for a human, while
    # the executable evidence stands.
    challenger_note = ""
    chal_verdict = verdict
    chal_abstentions = list(abstentions)
    if verdict == Verdict.CONFIRMED:
        outcome = challenge_confirmation(
            report, draft.summary, draft.repro_outcome or "", draft.repro_stdout,
            draft.repro_command, trajectory)
        challenger_note = outcome.note
        if outcome.revised:
            if trajectory.has_reproduced_artifact():
                # backed by real execution: keep the verdict, flag the dissent
                chal_abstentions.append(
                    "Adversarial reviewer raised an objection; confirmation is "
                    "backed by an observed reproduction, so it stands but a human "
                    "should review the objection.")
            else:
                chal_verdict = outcome.verdict
                chal_abstentions.append("Confirmation revised down after adversarial review.")
    out["challenge"] = snapshot(
        base_memo(chal_verdict, verified_claims, chal_abstentions, challenger_note,
                  with_sweep=True))

    return out
