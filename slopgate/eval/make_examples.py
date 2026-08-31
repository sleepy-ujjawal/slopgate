"""Generate a few example signed triage memos for the writeup and video.

The memo is the deliverable artifact, so the repo should ship a handful rendered
for representative cases: a genuine vulnerability confirmed, a slop report caught,
and the challenging misversioned case.

    python -m slopgate.eval.make_examples
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from slopgate.agent.memo import save_memo
from slopgate.agent.pipeline import run_pipeline
from slopgate.agent.schema import Report
from slopgate.model.trace import Trajectory

CASES = Path(__file__).resolve().parents[2] / "corpus" / "cases"
OUT = Path(__file__).resolve().parents[2] / "docs" / "examples"

REPRESENTATIVE = [
    ("pyyaml-truthful-0", "a genuine RCE, confirmed by reproduction"),
    ("pyyaml-vshift-0", "real gadget on a patched version — slop, caught"),
    ("pyyaml-challenge-0", "the challenging misversioned case"),
]


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass
    OUT.mkdir(parents=True, exist_ok=True)
    for cid, why in REPRESENTATIVE:
        case = json.loads((CASES / f"{cid}.json").read_text(encoding="utf-8"))
        report = Report.from_dict(case["report"])
        traj = Trajectory(case_id=f"example-{cid}")
        memo = run_pipeline(report, "challenge", traj)
        md, _ = save_memo(memo, OUT / cid)
        print(f"[{memo.verdict.value:22s}] {cid}  ({why})  -> {md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
