"""Verify that a real-CVE case's PoC actually behaves as its ground-truth claims.

    python -m slopgate.eval.verify_cases <glob-or-dir> [--keep-into DIR]

A case is only trustworthy if its PoC *executes* the way its label says — otherwise
the "ground truth" is just an assertion, the very thing this project refuses to
accept from a report. For each `confirmed` case with a PoC and a known fixed version,
this runs the PoC in the dynamic sandbox against BOTH:

  * the affected version  -> must be REPRODUCED
  * the fixed version     -> must be NOT_REPRODUCED

Only cases that pass both are sound (the PoC discriminates vulnerable from patched).
With --keep-into, verified case files are copied into DIR so a scaled corpus can be
assembled from candidates automatically. No LLM is involved — this is pure execution.
"""
from __future__ import annotations

import glob
import json
import shutil
import sys
from pathlib import Path
from typing import Optional

from slopgate.agent.triage import _extract_poc
from slopgate.sandbox.base import Target, get_runtime
from slopgate.sandbox.dynamic import attempt_reproduction_dynamic


def _reproduce(package: str, version: str, poc: str, ecosystem: str) -> str:
    if ecosystem == "python":
        return attempt_reproduction_dynamic(package, version, poc).outcome
    return get_runtime(ecosystem).reproduce(Target(ecosystem, package, version), poc).outcome


def _expand(args) -> list:
    paths = []
    for a in args:
        p = Path(a)
        if p.is_dir():
            paths.extend(sorted(str(x) for x in p.glob("*.json")))
        else:
            paths.extend(sorted(glob.glob(a)))
    return paths


def verify_one(path: str) -> dict:
    case = json.loads(Path(path).read_text(encoding="utf-8"))
    rep, gt = case["report"], case.get("ground_truth", {})
    pkg = rep["package"]
    aff = rep["affected_version"]
    fixed = gt.get("fixed_version")
    ecosystem = rep.get("ecosystem", "python")
    expected = gt.get("expected_verdict")
    poc = _extract_poc(rep["body"])

    result = {"case": Path(path).stem, "package": pkg, "affected": aff,
              "fixed": fixed, "expected": expected, "status": "SKIP",
              "affected_outcome": "-", "fixed_outcome": "-", "note": ""}

    if not poc:
        result["note"] = "no runnable PoC in body"
        return result
    if expected != "confirmed":
        result["note"] = "not a confirmed case (nothing to reproduce-verify)"
        return result

    result["affected_outcome"] = _reproduce(pkg, aff, poc, ecosystem)
    if fixed:
        result["fixed_outcome"] = _reproduce(pkg, fixed, poc, ecosystem)

    aff_ok = result["affected_outcome"] == "REPRODUCED"
    fixed_ok = (result["fixed_outcome"] == "NOT_REPRODUCED") if fixed else True
    result["status"] = "PASS" if (aff_ok and fixed_ok) else "FAIL"
    if not aff_ok:
        result["note"] = "PoC did NOT reproduce on the affected version"
    elif not fixed_ok:
        result["note"] = "PoC still fires on the fixed version (bad label or bad PoC)"
    return result


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    keep_into: Optional[str] = None
    if "--keep-into" in argv:
        i = argv.index("--keep-into")
        keep_into = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    paths = _expand(argv)
    if not paths:
        print("no case files matched", file=sys.stderr)
        return 2
    if keep_into:
        Path(keep_into).mkdir(parents=True, exist_ok=True)

    print(f"verifying {len(paths)} candidate case(s) by execution\n")
    header = f"{'case':<28} {'aff':<14} {'affected':<14} {'fixed':<14} status"
    print(header)
    print("-" * len(header))
    passed = 0
    for path in paths:
        try:
            r = verify_one(path)
        except Exception as exc:  # keep the run going; a bad candidate isn't fatal
            print(f"{Path(path).stem:<28} {'?':<14} ERROR {type(exc).__name__}: {exc}")
            continue
        print(f"{r['case']:<28} {r['affected']:<14} {r['affected_outcome']:<14} "
              f"{r['fixed_outcome']:<14} {r['status']}  {r['note']}")
        if r["status"] == "PASS":
            passed += 1
            if keep_into:
                shutil.copy(path, Path(keep_into) / Path(path).name)

    print(f"\n{passed}/{len(paths)} candidates verified as sound "
          "(PoC reproduces on affected, goes quiet on fixed).")
    if keep_into:
        print(f"verified cases copied into {keep_into}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
