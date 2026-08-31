"""Metrics for the baseline-vs-solution comparison.

The primary outcome is correct-verdict rate, but an aggregate accuracy hides the
thing a maintainer actually cares about, so we break errors into two kinds with
very different costs:

  * false-confirm  — signed 'confirmed' on a report whose true verdict is not
                     'confirmed'. This wastes the maintainer's time and, if acted
                     on, mis-assigns a CVE. It is the error the fidelity gate targets.
  * false-dismiss  — returned 'not_reproducible' on a report whose true verdict IS
                     'confirmed'. This is the dangerous direction: a real vulnerability
                     waved away. Abstaining ('insufficient_evidence') on a real vuln is
                     NOT counted as a dismissal — deferring to a human is the safe move.

The deterministic secondary metric is execution-fidelity: of all 'confirmed'
verdicts, the fraction backed by a real REPRODUCED artifact.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from slopgate.agent.schema import Verdict

CONFIRMED = Verdict.CONFIRMED.value
NOT_REPRO = Verdict.NOT_REPRODUCIBLE.value
INSUFFICIENT = Verdict.INSUFFICIENT.value


@dataclass
class StageMetrics:
    stage: str
    n: int = 0
    correct: int = 0
    false_confirm: int = 0
    false_dismiss: int = 0
    confirmed_total: int = 0
    confirmed_backed: int = 0     # of confirmed verdicts, how many had a real run
    abstentions: int = 0
    total_cost_usd: float = 0.0
    total_latency_s: float = 0.0
    total_tokens: int = 0
    per_case: list[dict] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        return self.correct / self.n if self.n else 0.0

    @property
    def false_confirm_rate(self) -> float:
        return self.false_confirm / self.n if self.n else 0.0

    @property
    def false_dismiss_rate(self) -> float:
        return self.false_dismiss / self.n if self.n else 0.0

    @property
    def execution_fidelity(self) -> float:
        # Vacuously perfect if nothing was confirmed.
        return self.confirmed_backed / self.confirmed_total if self.confirmed_total else 1.0

    @property
    def avg_cost_usd(self) -> float:
        return self.total_cost_usd / self.n if self.n else 0.0

    @property
    def avg_latency_s(self) -> float:
        return self.total_latency_s / self.n if self.n else 0.0


def score_case(sm: StageMetrics, *, expected: str, predicted: str,
               confirmed_backed: bool) -> None:
    sm.n += 1
    if predicted == expected:
        sm.correct += 1
    if predicted == CONFIRMED and expected != CONFIRMED:
        sm.false_confirm += 1
    if predicted == NOT_REPRO and expected == CONFIRMED:
        sm.false_dismiss += 1
    if predicted == CONFIRMED:
        sm.confirmed_total += 1
        if confirmed_backed:
            sm.confirmed_backed += 1
    if predicted == INSUFFICIENT:
        sm.abstentions += 1
