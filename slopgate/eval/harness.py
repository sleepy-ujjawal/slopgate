"""Run the corpus through every changelog stage and print the comparison table.

This is the single command a judge runs to reproduce the headline result. It
evaluates each case once (deriving all six stages from one triage execution),
scores every stage against the hidden ground truth, and prints:
  * the per-stage metrics table (accuracy, false-confirm, false-dismiss,
    execution-fidelity, abstention, avg cost/latency), and
  * the human-time / cost comparison the brief's metric table asks for.

Cases run concurrently (threads around network-bound LLM calls) because each
call carries ~40s of model thinking latency; a serial run would take far longer.

Usage:
    python -m slopgate.eval.harness                 # all cases, all stages
    python -m slopgate.eval.harness --limit 3       # quick subset
    python -m slopgate.eval.harness --workers 6
"""
from __future__ import annotations

import argparse
import json
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from slopgate.agent.pipeline import STAGES, evaluate_all_stages
from slopgate.agent.schema import Report
from slopgate.eval.metrics import StageMetrics, score_case
from slopgate.model.trace import Trajectory

CASES_DIR = Path(__file__).resolve().parents[2] / "corpus" / "cases"
RESULTS_DIR = Path(__file__).resolve().parents[2] / "runs" / "_eval"

# Documented human baseline for the cost table (curl, Stenberg 2025-07-14:
# "every report engages 3-4 persons, 30 min to 3 hours each"). We report the
# lower bound of one reviewer's time as a conservative per-report human cost.
HUMAN_MINUTES_PER_REPORT_LOW = 30


def load_cases(limit: int | None) -> list[dict]:
    files = sorted(CASES_DIR.glob("*.json"))
    if limit:
        files = files[:limit]
    return [json.loads(p.read_text(encoding="utf-8")) for p in files]


def run_one_case(case: dict, attempts: int = 2) -> dict:
    """Evaluate a single case across all stages. Returns a serializable result.

    A whole-case retry absorbs a transient model timeout on one of the ~6 calls,
    so a single slow request does not drop an entire case from the evaluation.
    """
    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            return _run_one_case(case)
        except Exception as exc:  # transient network/model failure
            last_exc = exc
    raise last_exc  # type: ignore[misc]


def _run_one_case(case: dict) -> dict:
    report = Report.from_dict(case["report"])
    traj = Trajectory(case_id=report.report_id)
    memos = evaluate_all_stages(report, traj)
    traj.render_markdown()
    return {
        "report_id": report.report_id,
        "expected": case["ground_truth"]["expected_verdict"],
        "injected_defect": case["ground_truth"]["injected_defect"],
        "stages": {
            s: {
                "verdict": m.verdict.value,
                "cost": m.est_cost_usd,
                "latency": m.wall_latency_s,
                "tokens": m.total_tokens,
                # "backed" = this stage's verdict is supported by a reproduction of
                # the CLAIMED version (not a sibling found by the sweep, and not the
                # shared trajectory). Baseline runs nothing, so it is never backed.
                "backed": bool(m.reproduction and m.reproduction.reproduced),
            }
            for s, m in memos.items()
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--workers", type=int, default=5)
    args = ap.parse_args()

    # Windows consoles/pipes default to cp1252, which cannot encode the glyphs
    # used below. Force UTF-8 so a print never crashes the whole evaluation.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass

    cases = load_cases(args.limit)
    if not cases:
        print("No cases found. Run: python -m slopgate.corpus.build", file=sys.stderr)
        return 1
    print(f"Evaluating {len(cases)} cases across {len(STAGES)} stages "
          f"({args.workers} workers)...\n")

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(run_one_case, c): c for c in cases}
        for fut in as_completed(futures):
            cid = futures[fut]["report"]["report_id"]
            try:
                res = fut.result()
                results.append(res)
                print(f"  [ok] {cid}: " + " ".join(
                    f"{s[:4]}={res['stages'][s]['verdict'][:4]}" for s in STAGES))
            except Exception as exc:
                print(f"  [XX] {cid}: {type(exc).__name__}: {exc}")
                traceback.print_exc()

    # --- aggregate per stage ---
    stage_metrics = {s: StageMetrics(stage=s) for s in STAGES}
    for res in results:
        for s in STAGES:
            sm = stage_metrics[s]
            sd = res["stages"][s]
            # backed is now per-stage: a confirmation counts as execution-backed
            # only if THIS stage's memo carries a reproduction of the claimed version.
            score_case(sm, expected=res["expected"], predicted=sd["verdict"],
                       confirmed_backed=sd["backed"])
            sm.total_cost_usd += sd["cost"]
            sm.total_latency_s += sd["latency"]
            sm.total_tokens += sd["tokens"]

    _print_table(stage_metrics)
    _print_cost_table(stage_metrics)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nPer-case results: {RESULTS_DIR / 'results.json'}")
    print(f"Trajectories:    runs/<report_id>/trajectory.md")
    return 0


def _print_table(sm_by_stage: dict[str, StageMetrics]) -> None:
    print("\n" + "=" * 92)
    print("STAGE COMPARISON  (same cases throughout)")
    print("=" * 92)
    hdr = f"{'stage':<10} {'acc':>6} {'false-confirm':>14} {'false-dismiss':>14} " \
          f"{'exec-fidelity':>14} {'abstain':>8}"
    print(hdr)
    print("-" * 92)
    for s in STAGES:
        m = sm_by_stage[s]
        print(f"{s:<10} {m.accuracy:>6.0%} "
              f"{m.false_confirm:>3}/{m.n:<2} ={m.false_confirm_rate:>5.0%} "
              f"{m.false_dismiss:>3}/{m.n:<2} ={m.false_dismiss_rate:>5.0%} "
              f"{m.execution_fidelity:>13.0%} {m.abstentions:>8}")


def _print_cost_table(sm_by_stage: dict[str, StageMetrics]) -> None:
    base = sm_by_stage["baseline"]
    full = sm_by_stage["challenge"]
    print("\n" + "=" * 92)
    print("PRIMARY OUTCOME / HUMAN TIME / COST  (baseline vs full solution)")
    print("=" * 92)
    print(f"{'metric':<28} {'human':>12} {'baseline':>12} {'solution':>12}")
    print("-" * 92)
    print(f"{'correct-verdict rate':<28} {'-':>12} "
          f"{base.accuracy:>11.0%} {full.accuracy:>11.0%}")
    print(f"{'false-confirm rate':<28} {'-':>12} "
          f"{base.false_confirm_rate:>11.0%} {full.false_confirm_rate:>11.0%}")
    print(f"{'exec-fidelity':<28} {'-':>12} "
          f"{base.execution_fidelity:>11.0%} {full.execution_fidelity:>11.0%}")
    print(f"{'time per report':<28} {str(HUMAN_MINUTES_PER_REPORT_LOW)+'+ min':>12} "
          f"{base.avg_latency_s:>10.0f}s {full.avg_latency_s:>10.0f}s")
    print(f"{'cost per report':<28} {'staff hours':>12} "
          f"${base.avg_cost_usd:>10.4f} ${full.avg_cost_usd:>10.4f}")
    print("\n(Human baseline: curl security team, Stenberg 2025-07-14 - every report "
          "engages 3-4 people, 30 min-3 h each.)")


if __name__ == "__main__":
    raise SystemExit(main())
