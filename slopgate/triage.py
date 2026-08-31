"""One report in, one signed maintainer memo out — the maintainer's flow.

    python -m slopgate.triage path/to/report.json
    python -m slopgate.triage path/to/report.json --save runs/my-triage

Accepts either a full case file (`{"report": {...}, "ground_truth": {...}}`) or a
bare report object (`{"report_id": ..., "package": ..., "affected_version": ...,
"title": ..., "body": ...}`). Runs the full agent (the `challenge` stage: reproduce
→ fidelity gate → abstain → verify → challenge → threat-model) and prints the memo a
maintainer can paste into their tracker. No verdict is ever auto-signed.

Needs a `GEMINI_API_KEY` in `.env` and Docker for the sandbox — the same as the
evaluation harnesses.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from slopgate.agent.memo import render_markdown, save_memo
from slopgate.agent.pipeline import STAGES, run_pipeline
from slopgate.agent.schema import Report
from slopgate.model.trace import Trajectory


def main(argv=None) -> int:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass

    ap = argparse.ArgumentParser(
        description="Triage one vulnerability report into a signed maintainer memo.")
    ap.add_argument("report", help="path to a report JSON (case file or bare report)")
    ap.add_argument("--stage", default="challenge", choices=STAGES,
                    help="pipeline stage to run (default: the full 'challenge' agent)")
    ap.add_argument("--save", metavar="DIR",
                    help="also write memo.md and memo.json into DIR")
    args = ap.parse_args(argv)

    try:
        data = json.loads(Path(args.report).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read report JSON: {exc}", file=sys.stderr)
        return 2
    # Accept a case file ({"report": {...}}) or a bare report dict.
    report = Report.from_dict(data.get("report", data))

    trajectory = Trajectory(case_id=f"triage-{report.report_id}")
    memo = run_pipeline(report, args.stage, trajectory)

    print(render_markdown(memo))

    if args.save:
        md, js = save_memo(memo, Path(args.save))
        print(f"\n[saved] {md}  ·  {js}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
