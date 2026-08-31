"""Turn runs/_eval/results.json into the Markdown tables used in the README.

Keeping this separate from the console harness means the writeup's numbers are
regenerated from the saved evidence rather than transcribed by hand -- run it
after the harness and paste, or pipe, the output into the README.

    python -m slopgate.eval.report_md
"""
from __future__ import annotations

import json
from pathlib import Path

from slopgate.agent.pipeline import STAGES
from slopgate.eval.metrics import StageMetrics, score_case

RESULTS = Path(__file__).resolve().parents[2] / "runs" / "_eval" / "results.json"

STAGE_STORY = {
    "baseline": "Single prompt, no tools. What a swamped maintainer does.",
    "tool": "Agent authors and **runs** a PoC in the sandbox.",
    "gate": "Deterministic gate downgrades any confirmation with no real run.",
    "abstain": "Undecidable reproductions become human-review deferrals.",
    "verify": "Independent per-claim check against the evidence.",
    "challenge": "Adversarial review defends every surviving confirmation.",
}


def _aggregate(results: list[dict]) -> dict[str, StageMetrics]:
    sm = {s: StageMetrics(stage=s) for s in STAGES}
    for res in results:
        for s in STAGES:
            m = sm[s]
            sd = res["stages"][s]
            score_case(m, expected=res["expected"], predicted=sd["verdict"],
                       confirmed_backed=sd.get("backed", False))
            m.total_cost_usd += sd["cost"]
            m.total_latency_s += sd["latency"]
            m.total_tokens += sd["tokens"]
    return sm


def main() -> int:
    results = json.loads(RESULTS.read_text(encoding="utf-8"))
    sm = _aggregate(results)
    n = sm["baseline"].n

    print(f"### Measured on {n} cases (same cases at every stage)\n")
    print("| Stage | What it adds | Accuracy | False-confirm | False-dismiss | "
          "Exec-fidelity | Abstain | $/report |")
    print("|---|---|---|---|---|---|---|---|")
    for s in STAGES:
        m = sm[s]
        print(f"| **{s}** | {STAGE_STORY[s]} | {m.accuracy:.0%} | "
              f"{m.false_confirm}/{m.n} ({m.false_confirm_rate:.0%}) | "
              f"{m.false_dismiss}/{m.n} ({m.false_dismiss_rate:.0%}) | "
              f"{m.execution_fidelity:.0%} | {m.abstentions} | "
              f"${m.avg_cost_usd:.4f} |")

    base, full = sm["baseline"], sm["challenge"]
    print("\n**Headline:** baseline false-confirm "
          f"{base.false_confirm_rate:.0%} → full solution {full.false_confirm_rate:.0%}; "
          f"accuracy {base.accuracy:.0%} → {full.accuracy:.0%}; "
          f"execution-fidelity {base.execution_fidelity:.0%} → {full.execution_fidelity:.0%}. "
          f"Cost ~${full.avg_cost_usd:.3f}/report vs a documented 30 min–3 h of human time.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
