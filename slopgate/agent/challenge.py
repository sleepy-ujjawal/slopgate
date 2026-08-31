"""Adversarial challenger: argue against a confirmation, force a defence.

Only a 'confirmed' verdict is worth challenging -- a not-reproducible or
abstaining verdict is already the cautious side. The challenger is handed the
same evidence and told to make the strongest case that the confirmation is
wrong (wrong version, the output does not actually show the claimed impact, the
PoC proves something benign). The pipeline then requires the confirmation to
survive: if the challenger raises a concrete, evidence-grounded objection that
the reproduction does not rebut, the verdict is revised down to abstention.

This guards a specific over-confidence: a real REPRODUCED artifact that proves a
*different* thing than the report claimed. The fidelity gate checks that a run
happened; the challenger checks that the run proved the right claim.
"""
from __future__ import annotations

from dataclasses import dataclass

from slopgate.agent.llm import ask_json
from slopgate.agent.schema import Report, Verdict
from slopgate.model.trace import Trajectory

AGENT = "challenger"

SYSTEM = (
    "You are a red-team reviewer. Your job is to argue, as strongly as the "
    "evidence honestly allows, that a 'confirmed' vulnerability verdict is WRONG. "
    "Look for: the reproduction ran against a different version than claimed; the "
    "output demonstrates benign behaviour rather than the claimed security impact; "
    "the PoC proves a crash but not the claimed exploit. If, after your best "
    "effort, the confirmation still holds up, say so honestly."
)


@dataclass
class ChallengeOutcome:
    verdict: Verdict
    revised: bool
    note: str


def challenge_confirmation(
    report: Report, summary: str, outcome: str, stdout: str, command: str,
    trajectory: Trajectory,
) -> ChallengeOutcome:
    prompt = (
        f"Report claim: {report.title} in {report.package} {report.affected_version}.\n"
        f"Triage summary: {summary}\n"
        f"Reproduction command: {command}\n"
        f"Reproduction outcome: {outcome}\nOutput:\n{stdout[:2000]}\n\n"
        "Return JSON: {\"objection_holds\": bool, \"reason\": \"...\"}. "
        "Set objection_holds=true ONLY if you found a concrete, evidence-grounded "
        "reason the confirmation is unsound. Otherwise false."
    )
    data, _ = ask_json(trajectory, agent=AGENT, system=SYSTEM, prompt=prompt)
    data = data or {}
    holds = bool(data.get("objection_holds"))
    reason = str(data.get("reason", "")).strip()

    if holds:
        trajectory.note(agent=AGENT, message="objection upheld; revising confirmation down to abstention",
                        data={"reason": reason})
        return ChallengeOutcome(Verdict.INSUFFICIENT, revised=True,
                                note=f"Challenger objection: {reason}")
    trajectory.note(agent=AGENT, message="confirmation survived challenge", data={"reason": reason})
    return ChallengeOutcome(Verdict.CONFIRMED, revised=False,
                            note=f"Confirmation upheld against challenge. {reason}".strip())
