"""The execution-fidelity gate: a 'confirmed' verdict must be earned by a run.

This is deterministic on purpose. Every other stage is an LLM that can be talked
into agreeing with a confident report. This stage cannot: it inspects the
trajectory for an actual reproduction tool call that returned REPRODUCED, and if
there is none, it downgrades any 'confirmed' verdict. It is the single most
important line of defence against the project's core failure mode -- an agent
signing off on slop it never executed.

The gate is also the deterministic secondary metric: execution-fidelity is simply
"of all 'confirmed' verdicts, what fraction were backed by a real REPRODUCED
artifact." By construction, after this gate runs, that fraction is 1.0.
"""
from __future__ import annotations

from dataclasses import dataclass

from slopgate.agent.schema import Verdict
from slopgate.model.trace import Trajectory


@dataclass
class GateOutcome:
    verdict: Verdict
    downgraded: bool
    reason: str


def apply_fidelity_gate(
    proposed: Verdict, trajectory: Trajectory
) -> GateOutcome:
    backed = trajectory.has_reproduced_artifact()

    if proposed == Verdict.CONFIRMED and not backed:
        trajectory.note(
            agent="fidelity_gate",
            message="DOWNGRADED: 'confirmed' had no REPRODUCED artifact in the trajectory",
        )
        return GateOutcome(
            verdict=Verdict.NOT_REPRODUCIBLE,
            downgraded=True,
            reason="No reproduction tool call returned REPRODUCED; a confirmation "
                   "requires an observed reproduction.",
        )

    if proposed == Verdict.CONFIRMED and backed:
        trajectory.note(agent="fidelity_gate", message="upheld: confirmation backed by a real reproduction")
        return GateOutcome(verdict=proposed, downgraded=False,
                           reason="Confirmation backed by an observed reproduction.")

    return GateOutcome(verdict=proposed, downgraded=False,
                       reason="No confirmation to gate.")
