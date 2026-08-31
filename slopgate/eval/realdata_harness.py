"""Run SlopGate against REAL advisories with dynamic environment provisioning.

Unlike the synthetic harness, cases here name real PyPI packages; the agent
writes a PoC and the sandbox provisions the actual package from PyPI to run it.
Ground truth comes from the real advisory (published vs withdrawn, affected vs
patched version). Because reproducing an arbitrary real CVE requires the agent to
author a working exploit, this also honestly measures REACHABILITY — how often
execution-based triage can reach a verdict at all.

    python -m slopgate.eval.realdata_harness            # all real cases
    python -m slopgate.eval.realdata_harness --limit 2
"""
from __future__ import annotations

import argparse
import json
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from slopgate.agent.pipeline import run_pipeline
from slopgate.agent.schema import Report, Verdict
from slopgate.model.trace import Trajectory

CASES_DIR = Path(__file__).resolve().parents[2] / "realdata" / "cases"
OUT = Path(__file__).resolve().parents[2] / "runs" / "_realdata"


def _reconfig():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass


def run_case(case: dict) -> dict:
    report = Report.from_dict(case["report"])
    gt = case["ground_truth"]
    # baseline (single prompt, no tools) vs full solution (challenge stage)
    tb = Trajectory(case_id=f"real-{report.report_id}-baseline")
    base = run_pipeline(report, "baseline", tb)
    tf = Trajectory(case_id=f"real-{report.report_id}")
    full = run_pipeline(report, "challenge", tf)
    tf.render_markdown()
    repro = full.reproduction
    return {
        "report_id": report.report_id,
        "package": gt.get("package"),
        "affected_version": report.affected_version,
        "expected": gt["expected_verdict"],
        "baseline": base.verdict.value,
        "solution": full.verdict.value,
        "repro_outcome": repro.outcome if repro else "NO_POC",
        "reproduced": bool(repro and repro.reproduced),
        "source": gt.get("source"),
        "cve": gt.get("cve"),
    }


def main() -> int:
    _reconfig()
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--workers", type=int, default=3)
    args = ap.parse_args()

    files = sorted(CASES_DIR.glob("*.json"))
    if args.limit:
        files = files[: args.limit]
    cases = [json.loads(p.read_text(encoding="utf-8")) for p in files]
    if not cases:
        print("No real cases in realdata/cases/. Add some first.", file=sys.stderr)
        return 1
    print(f"Running {len(cases)} REAL advisories (dynamic provisioning)…\n")

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {pool.submit(run_case, c): c for c in cases}
        for fut in as_completed(futs):
            cid = futs[fut]["report"]["report_id"]
            try:
                r = fut.result()
                results.append(r)
                print(f"  [ok] {cid:24s} repro={r['repro_outcome']:16s} "
                      f"base={r['baseline'][:4]} sol={r['solution'][:4]} exp={r['expected'][:4]}")
            except Exception as exc:
                print(f"  [XX] {cid}: {type(exc).__name__}: {exc}")
                traceback.print_exc()

    _report(results)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nPer-case: {OUT/'results.json'}   Trajectories: runs/real-<id>/trajectory.md")
    return 0


def _report(results: list[dict]) -> None:
    n = len(results)
    if not n:
        return
    base_ok = sum(r["baseline"] == r["expected"] for r in results)
    sol_ok = sum(r["solution"] == r["expected"] for r in results)
    reached = sum(r["reproduced"] for r in results)
    # false-confirm: said 'confirmed' when expected is not confirmed
    base_fc = sum(r["baseline"] == "confirmed" and r["expected"] != "confirmed" for r in results)
    sol_fc = sum(r["solution"] == "confirmed" and r["expected"] != "confirmed" for r in results)
    print("\n" + "=" * 78)
    print("REAL-WORLD RESULTS  (real PyPI advisories, dynamic provisioning)")
    print("=" * 78)
    print(f"cases: {n}")
    print(f"reproduced (reachability): {reached}/{n} ({reached/n:.0%})")
    print(f"accuracy       baseline {base_ok}/{n} ({base_ok/n:.0%})   "
          f"solution {sol_ok}/{n} ({sol_ok/n:.0%})")
    print(f"false-confirm  baseline {base_fc}/{n} ({base_fc/n:.0%})   "
          f"solution {sol_fc}/{n} ({sol_fc/n:.0%})")
    print("\nNote: 'reachability' is how often the agent's self-written PoC actually "
          "reproduced. Where it cannot, the system abstains rather than guessing — "
          "that is the honest ceiling of execution-based triage on arbitrary CVEs.")


if __name__ == "__main__":
    raise SystemExit(main())
