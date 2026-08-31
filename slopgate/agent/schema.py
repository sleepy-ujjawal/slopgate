"""Data contracts for the triage pipeline.

Dataclasses, not Pydantic: the host side stays dependency-free. Validation is
explicit and small because the only untrusted structured input is a case file we
author, and the only model-produced structures are parsed leniently at the call
site and coerced here.

Vocabulary:
  Verdict — the three states a maintainer actually needs. "confirmed" is a claim
  about the world that must be backed by an execution artifact; "not_reproducible"
  means we tried and it did not hold; "insufficient_evidence" is honest abstention,
  routed to a human. There is deliberately no "reject as slop" verdict: the system
  never asserts a report is fake, only that it could not confirm it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    NOT_REPRODUCIBLE = "not_reproducible"
    INSUFFICIENT = "insufficient_evidence"

    @classmethod
    def coerce(cls, value: Any) -> "Verdict":
        if isinstance(value, cls):
            return value
        text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        for member in cls:
            if text == member.value or text == member.name.lower():
                return member
        # Unknown/garbled model output is treated as abstention, never confirmation.
        return cls.INSUFFICIENT


@dataclass
class Report:
    """An incoming vulnerability report — the thing being adjudicated."""
    report_id: str
    package: str
    affected_version: str
    title: str
    body: str
    reporter: str = "anonymous"
    ecosystem: str = "python"   # which sandbox runtime reproduces this (python | c)

    @staticmethod
    def from_dict(d: dict) -> "Report":
        return Report(
            report_id=d["report_id"],
            package=d["package"],
            affected_version=d["affected_version"],
            title=d["title"],
            body=d["body"],
            reporter=d.get("reporter", "anonymous"),
            ecosystem=d.get("ecosystem", "python"),
        )


@dataclass
class Claim:
    """One atomic assertion extracted from the report, with its adjudication."""
    text: str
    supported: Optional[bool] = None   # None until the verifier rules on it
    evidence: str = ""                 # what supports or refutes it


@dataclass
class ReproEvidence:
    """The record of a reproduction attempt — the spine of an honest 'confirmed'."""
    env_id: str
    outcome: str            # REPRODUCED / NOT_REPRODUCED / ERRORED / ...
    reproduced: bool
    command: str
    stdout_tail: str
    poc: str


@dataclass
class TriageMemo:
    """The signable professional artifact this whole system exists to produce."""
    report_id: str
    package: str
    affected_version: str
    verdict: Verdict
    summary: str
    claims: list[Claim] = field(default_factory=list)
    reproduction: Optional[ReproEvidence] = None
    abstentions: list[str] = field(default_factory=list)   # what needs a human
    challenger_note: str = ""                               # dissent, if any
    slop_advisory: str = ""                                 # warn-only name-slop note
    reviewer: str = "PENDING HUMAN REVIEW"                  # never auto-signed

    # accounting, filled by the pipeline for the metrics table
    llm_calls: int = 0
    total_tokens: int = 0
    est_cost_usd: float = 0.0
    wall_latency_s: float = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d

    def save_json(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
