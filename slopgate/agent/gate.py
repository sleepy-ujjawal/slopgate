"""The execution-fidelity gate: the verdict must match what actually ran.

This is deterministic on purpose. Every other stage is an LLM that can be talked
into (or nondeterministically flip to) the wrong answer. This stage cannot. It is
**symmetric** -- it guards both directions of the execution/verdict contract:

  * `apply_fidelity_gate`      -- never CONFIRM without a run. If a 'confirmed'
    verdict has no REPRODUCED artifact in the trajectory, downgrade it. This is the
    defence against the core failure mode: signing off on slop that was never run.

  * `apply_reproduction_floor` -- never DISMISS despite a run. If the claimed
    version actually REPRODUCED, the verdict may not be 'not_reproducible', even if
    the model's verdict call said so. This is the defence against the mirror (and
    more dangerous) failure: waving away a vulnerability that genuinely reproduced.

The gate is also the deterministic secondary metric: execution-fidelity is simply
"of all 'confirmed' verdicts, what fraction were backed by a real REPRODUCED
artifact." By construction, after this gate runs, that fraction is 1.0 -- and, with
the floor, no reproduced-on-the-claimed-version report is ever left dismissed.
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


def apply_reproduction_floor(
    proposed: Verdict, reproduced_on_claimed: bool, trajectory: Trajectory
) -> GateOutcome:
    """The mirror of the fidelity gate: a proven vulnerability is never dismissed.

    `reproduced_on_claimed` is the CLAIMED-version reproduction result
    (``TriageDraft.reproduced``), deliberately NOT the sweep-inclusive
    ``trajectory.has_reproduced_artifact()`` -- a version-shift slop report whose PoC
    only reproduces on a *sibling* version must stay ``not_reproducible``, and its
    claimed-version signal is False, so the floor correctly never fires for it.
    """
    if reproduced_on_claimed and proposed == Verdict.NOT_REPRODUCIBLE:
        trajectory.note(
            agent="fidelity_gate",
            message="CORRECTED UP: 'not_reproducible' contradicts a REPRODUCED "
                    "artifact on the claimed version",
        )
        return GateOutcome(
            verdict=Verdict.CONFIRMED,
            downgraded=True,
            reason="Reproduced on the claimed version; the verdict cannot be "
                   "not_reproducible.",
        )

    return GateOutcome(verdict=proposed, downgraded=False,
                       reason="No dismissal to correct.")
