"""Warn-only pipeline hook for the AI-slop name classifier.

Mirrors the *non-downgrading* advisory path of `apply_threat_model_gate`: it records
a trajectory note and returns a human-facing string, but it NEVER touches the verdict.
The whole point of R2's resolution is that name-slop detection ships in warn-only mode
until its false-positive rate is measured, so there is deliberately no verdict lever
here to pull.
"""
from __future__ import annotations

from dataclasses import dataclass

from slopgate.agent.schema import Report
from slopgate.model.trace import Trajectory
from slopgate.slop.classifier import SlopScore, score_slop
from slopgate.slop.pypi import fetch_metadata

AGENT = "slop_advisory"


@dataclass
class SlopOutcome:
    advisory: str          # empty unless the name crosses the warn threshold
    score: SlopScore


def apply_slop_advisory(report: Report, trajectory: Trajectory, *,
                        use_network: bool = True) -> SlopOutcome:
    meta = None
    if use_network:
        try:
            meta = fetch_metadata(report.package)
        except Exception:
            meta = None            # warn-only: a lookup failure must never break triage

    score = score_slop(report.package, meta)
    trajectory.note(
        agent=AGENT,
        message=(f"AI-slop name score {score.score:.2f} / {score.threshold:.2f} "
                 f"(warn-only, verdict unchanged)"),
        data={"would_flag": score.would_flag, "vectors": score.vectors,
              "reason": score.reason},
    )

    advisory = ""
    if score.would_flag:
        advisory = (
            f"SLOP-ADVISORY (warn-only, does not change the verdict): the package "
            f"name '{report.package}' scores {score.score:.2f} on the AI-slop name "
            f"heuristic — {score.reason}. Confirm it is a real, intended dependency "
            f"before acting on this report."
        )
    return SlopOutcome(advisory, score)
