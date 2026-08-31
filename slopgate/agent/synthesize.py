"""Prose-to-PoC synthesis: reach a verdict when the report carries no PoC.

Real reports often describe a vulnerability without shipping a runnable
proof-of-concept. Rather than abstain on every such report, the agent writes a
PoC itself and runs it in the sandbox — a bounded self-correction loop: write,
run, read the error, fix, retry. This is defensive verification of a public,
patched vulnerability class; the loop is capped and the synthesized code is never
kept beyond the run.

The danger is a synthesized PoC that prints the success marker without actually
demonstrating the claimed impact — that would confirm a non-vulnerability. So a
synthesized reproduction is not trusted on its own: demonstrates_claim() is a
separate check that the PoC really exercises the claimed behaviour, and only then
does the downstream pipeline let the confirmation stand.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from slopgate.agent.llm import ask, ask_json
from slopgate.agent.schema import Report
from slopgate.agent.tools import reproduce_auto
from slopgate.model.trace import Trajectory

AGENT = "synthesizer"
MAX_ATTEMPTS = 3

# outcomes that mean "the PoC itself failed to run" -> worth another attempt
_RETRYABLE = {"ERRORED", "INCONCLUSIVE", "PROVISION_FAILED", "HARNESS_ERROR",
              "AMBIGUOUS", "NO_POC"}

_LANG = {"python": "Python", "c": "C"}
_FENCE = {"python": "python", "c": "c"}


def _system(ecosystem: str) -> str:
    lang = _LANG.get(ecosystem, "Python")
    return (
        f"You are a security engineer verifying a vulnerability report by writing a "
        f"minimal, self-contained {lang} proof-of-concept and running it in an "
        f"isolated, network-free sandbox. The PoC must demonstrate the SPECIFIC "
        f"claimed impact against the named package/version and be decisive: it must "
        f'print exactly "SLOPGATE:REPRODUCED" if the claimed behaviour is observed, '
        f'or "SLOPGATE:NOT_REPRODUCED" if it is not. Prefer an observable side '
        f"effect (create a file, set a sentinel) over asserting success. Do not "
        f"fabricate success: if the claim does not actually hold on this version, "
        f"the PoC must print NOT_REPRODUCED. Return ONLY the code."
    )


def _first_prompt(report: Report, ecosystem: str) -> str:
    return (
        f"Report: {report.title}\nPackage: {report.package} {report.affected_version}\n\n"
        f"{report.body[:2500]}\n\n"
        f"Write a self-contained {_LANG.get(ecosystem,'Python')} PoC (marker "
        f"convention above) that decisively tests whether this specific claim holds "
        f"on {report.package} {report.affected_version}. Return JSON: "
        '{"poc": "<the full source>"}.'
    )


def _retry_prompt(prev_poc: str, outcome: str, stderr: str, ecosystem: str) -> str:
    return (
        f"The previous PoC did not run cleanly (outcome: {outcome}). Fix it so it "
        f"runs and prints one of the two markers. Do not weaken the test — it must "
        f"still demonstrate the claimed impact honestly.\n\n"
        f"Previous PoC:\n```{_FENCE.get(ecosystem,'python')}\n{prev_poc}\n```\n\n"
        f"Error output:\n{stderr[:1500]}\n\n"
        'Return JSON: {"poc": "<the corrected full source>"}.'
    )


@dataclass
class SynthResult:
    outcome: str
    stdout: str
    command: str
    poc: Optional[str]
    attempts: int
    reproduced: bool


def synthesize_and_run(
    report: Report, ecosystem: str, trajectory: Trajectory,
    max_attempts: int = MAX_ATTEMPTS,
) -> SynthResult:
    poc: Optional[str] = None
    last = None
    for attempt in range(1, max_attempts + 1):
        if attempt == 1 or last is None:
            # first try, or the previous attempt produced no usable PoC at all
            data, _ = ask_json(trajectory, agent=AGENT, system=_system(ecosystem),
                               prompt=_first_prompt(report, ecosystem))
        else:
            data, _ = ask_json(trajectory, agent=AGENT, system=_system(ecosystem),
                               prompt=_retry_prompt(poc or "", last.outcome,
                                                    getattr(last, "stderr", ""), ecosystem))
        poc = (data or {}).get("poc") if isinstance(data, dict) else None
        if not poc:
            trajectory.note(agent=AGENT, message="model returned no PoC", data={"attempt": attempt})
            continue

        result = reproduce_auto(trajectory, agent=AGENT, package=report.package,
                                version=report.affected_version, poc_code=poc,
                                ecosystem=ecosystem)
        last = result
        trajectory.note(agent=AGENT, message=f"synthesis attempt {attempt}: {result.outcome}",
                        data={"attempt": attempt})
        if result.outcome not in _RETRYABLE:
            # decisive: REPRODUCED or a clean NOT_REPRODUCED
            return SynthResult(result.outcome, result.stdout, result.command, poc,
                               attempt, result.confirms_vulnerability())

    if last is not None:
        return SynthResult(last.outcome, last.stdout, last.command, poc,
                           max_attempts, last.confirms_vulnerability())
    return SynthResult("NO_POC", "", "", poc, max_attempts, False)


DEMO_SYSTEM = (
    "You are an independent reviewer. A proof-of-concept was AUTO-GENERATED by an "
    "agent (not supplied by the reporter) and it printed the success marker. Your "
    "job is to decide whether the PoC genuinely demonstrates the report's CLAIMED "
    "impact, or whether it merely prints the marker without proving the claim "
    "(e.g. it triggers unrelated behaviour, hard-codes the side effect, or tests a "
    "weaker property than claimed). Be strict: a synthesized PoC only counts if the "
    "code path it exercises is the one the report describes."
)


def demonstrates_claim(
    report: Report, poc: str, outcome: str, stdout: str, trajectory: Trajectory
) -> bool:
    prompt = (
        f"Claimed vulnerability: {report.title} in {report.package} "
        f"{report.affected_version}.\nReport:\n{report.body[:1500]}\n\n"
        f"Auto-generated PoC:\n```\n{poc[:2500]}\n```\n\n"
        f"Reproduction outcome: {outcome}\nOutput:\n{stdout[:800]}\n\n"
        'Return JSON: {"demonstrates_claim": true|false, "reason": "one sentence"}. '
        "true only if the PoC exercises the specific claimed code path/impact."
    )
    data, _ = ask_json(trajectory, agent="demo_check", system=DEMO_SYSTEM, prompt=prompt)
    ok = bool((data or {}).get("demonstrates_claim"))
    trajectory.note(agent="demo_check",
                    message=f"synthesized PoC demonstrates claim: {ok}",
                    data={"reason": str((data or {}).get("reason", ""))[:200]})
    return ok
