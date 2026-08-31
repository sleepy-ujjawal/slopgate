"""Measure the AI-slop name classifier before anyone would auto-block on it.

    python -m slopgate.slop.eval            # live PyPI (cached), full metrics
    python -m slopgate.slop.eval --offline  # mimicry-only, no network

Two labeled corpora live in `cases/`: `legit.json` (real, recently-published
packages — ground truth NOT slop) and `slop.json` (invented plausible compound
names — ground truth slop). The headline number is the **false-positive rate**: how
often a real package is flagged. That is the exact evidence the Round-3 review said
must exist before the enterprise design's synchronous auto-BLOCK is defensible; until
it does, the classifier stays warn-only. Recall (slop caught) is reported alongside.

A high FP rate here is a finding, not a bug: the vectors intentionally overlap with
legitimate young packages, and this harness is how we quantify that overlap.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from slopgate.slop.classifier import score_slop
from slopgate.slop.pypi import PkgMeta, fetch_metadata

CASES_DIR = Path(__file__).resolve().parent / "cases"


@dataclass
class SlopMetrics:
    n: int = 0
    flagged: int = 0
    true_positive: int = 0     # slop correctly flagged
    false_positive: int = 0    # legit wrongly flagged
    per_case: list = field(default_factory=list)

    @property
    def false_positive_rate(self) -> float:
        legit = self.n_legit
        return self.false_positive / legit if legit else 0.0

    @property
    def recall(self) -> float:
        slop = self.n_slop
        return self.true_positive / slop if slop else 0.0

    n_legit: int = 0
    n_slop: int = 0


def _load(name: str) -> list:
    return json.loads((CASES_DIR / name).read_text(encoding="utf-8"))


def _fmt_meta(meta: Optional[PkgMeta]) -> str:
    if meta is None:
        return "pypi:unknown"
    if not meta.exists:
        return "pypi:absent"
    age = meta.age_days
    age_s = f"{age:.0f}d" if age is not None else "?"
    prov = "prov" if meta.has_provenance else "no-prov"
    return f"age={age_s},{prov}"


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    offline = "--offline" in argv
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    corpus = [(c, "legit") for c in _load("legit.json")] + \
             [(c, "slop") for c in _load("slop.json")]

    m = SlopMetrics()
    any_network = False
    header = f"{'package':<34} {'truth':<6} {'score':>6} {'flag':<5} pypi-signal"
    print("R2 AI-slop name classifier — "
          f"{'OFFLINE (mimicry only)' if offline else 'live PyPI (cached)'}\n")
    print(header)
    print("-" * (len(header) + 6))

    for case, truth in corpus:
        name = case["name"]
        meta = None if offline else fetch_metadata(name)
        if meta is not None:
            any_network = True
        s = score_slop(name, meta)
        m.n += 1
        if truth == "legit":
            m.n_legit += 1
        else:
            m.n_slop += 1
        if s.would_flag:
            m.flagged += 1
            if truth == "slop":
                m.true_positive += 1
            else:
                m.false_positive += 1
        flag = "FLAG" if s.would_flag else "-"
        print(f"{name:<34} {truth:<6} {s.score:>6.2f} {flag:<5} {_fmt_meta(meta)}")
        m.per_case.append((name, truth, s.score, s.would_flag))

    print(f"\nlegit packages:   {m.n_legit}")
    print(f"slop packages:    {m.n_slop}")
    print(f"false positives:  {m.false_positive}/{m.n_legit}  "
          f"(FP rate {m.false_positive_rate:.0%})")
    print(f"recall on slop:   {m.true_positive}/{m.n_slop}  ({m.recall:.0%})")

    if offline or not any_network:
        print("\nNOTE: no live PyPI signal was used, so scores are mimicry-only and "
              "cannot cross the flag threshold by design. Run without --offline (with "
              "network) for the real false-positive-rate measurement.")
    else:
        print("\nInterpretation: the FP rate is the number that gates auto-blocking. "
              "While it is non-zero, the classifier must stay warn-only — which is "
              "exactly how it is wired into the pipeline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
