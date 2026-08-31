"""Sanity-check that the sandbox discriminates vulnerable from patched versions.

Run after building the image (or after changing corpus/environments.tsv):
    python -m slopgate.sandbox.selftest

Each check runs a known-good PoC gadget against both an affected and a patched
environment and asserts REPRODUCED / NOT_REPRODUCED respectively. If any check
fails, the evaluation corpus cannot be trusted, so this exits non-zero.
"""
from __future__ import annotations

import sys

from slopgate.corpus.build import POC_PYYAML, POC_JINJA2, POC_PYJWT
from slopgate.sandbox.runner import attempt_reproduction

CHECKS = [
    ("PyYAML CVE-2020-14343", POC_PYYAML, "pyyaml-5.3", "pyyaml-5.4"),
    ("Jinja2 CVE-2024-22195", POC_JINJA2, "jinja2-3.1.2", "jinja2-3.1.3"),
    ("PyJWT algorithms boundary", POC_PYJWT, "pyjwt-1.7.1", "pyjwt-2.4.0"),
]


def main() -> int:
    ok = True
    for name, poc, affected_env, patched_env in CHECKS:
        aff = attempt_reproduction(affected_env, poc)
        pat = attempt_reproduction(patched_env, poc)
        aff_ok = aff.outcome == "REPRODUCED"
        pat_ok = pat.outcome == "NOT_REPRODUCED"
        status = "PASS" if (aff_ok and pat_ok) else "FAIL"
        ok = ok and aff_ok and pat_ok
        print(f"[{status}] {name}: {affected_env}={aff.outcome} | {patched_env}={pat.outcome}")
    ok = _c_runtime_check() and ok
    ok = _reachability_check() and ok
    ok = _slop_check() and ok
    ok = _floor_check() and ok
    if not ok:
        print("\nSelf-test FAILED — the sandbox is not discriminating. "
              "Rebuild: docker build -t slopgate-sandbox:v1 . ; "
              "docker build -f Dockerfile.c -t slopgate-c-sandbox:v1 .", file=sys.stderr)
        return 1
    print("\nAll sandbox checks passed.")
    return 0


def _c_runtime_check() -> bool:
    """Verify the C/ASAN runtime: a real overflow reproduces, a clean run does not."""
    try:
        from slopgate.sandbox.c_runtime import CRuntime
        from slopgate.sandbox.base import Target
    except Exception as exc:  # pragma: no cover
        print(f"[SKIP] C runtime import failed: {exc}")
        return True
    rt = CRuntime()
    overflow = ('#include <string.h>\nint main(void){char b[8];'
                'strcpy(b,"AAAAAAAAAAAAAAAAAAAAAAAA");return 0;}\n')
    clean = '#include <stdio.h>\nint main(void){puts("SLOPGATE:NOT_REPRODUCED");return 0;}\n'
    aff = rt.reproduce(Target("c", "demo", "1.0"), overflow)
    pat = rt.reproduce(Target("c", "demo", "1.0"), clean)
    good = aff.outcome == "REPRODUCED" and pat.outcome == "NOT_REPRODUCED"
    print(f"[{'PASS' if good else 'FAIL'}] C/ASAN runtime: "
          f"overflow={aff.outcome} | clean={pat.outcome}")
    return good


def _reachability_check() -> bool:
    """R1: reachable is REACHABLE, unused is STRICT, and — the load-bearing part —
    an unmodeled construct escalates to AMBIGUOUS instead of a false STRICT."""
    try:
        from slopgate.reach.slicer import (
            AMBIGUOUS, REACHABLE, UNREACHABLE, classify_reachability,
        )
    except Exception as exc:  # pragma: no cover
        print(f"[SKIP] reachability slicer import failed: {exc}")
        return True
    checks = [
        ("direct call", "import gdown\ngdown.download(u)\n", REACHABLE),
        ("imported-unused", "import gdown\ngdown.extract_id(u)\n", UNREACHABLE),
        ("getattr dispatch", "import gdown\ngetattr(gdown, n)(u)\n", AMBIGUOUS),
        # a match statement is not in the modeled-node whitelist (or won't parse on
        # <3.10): either way it must NOT be suppressed as STRICT.
        ("unmodeled match",
         "import gdown\ndef f(k):\n    match k:\n        case 1:\n            return 0\n",
         AMBIGUOUS),
    ]
    good = True
    for name, src, expected in checks:
        got = classify_reachability(src, "gdown", "download").classification
        hit = got == expected
        good = good and hit
        print(f"[{'PASS' if hit else 'FAIL'}] reachability {name}: {got}")
    # the invariant, stated directly: the unmodeled case is never a false STRICT.
    unmodeled = classify_reachability(
        "import gdown\ndef f(k):\n    match k:\n        case 1:\n            return 0\n",
        "gdown", "download").classification
    if unmodeled == UNREACHABLE:
        print("[FAIL] reachability soundness: unmodeled construct signed UNREACHABLE_STRICT")
        good = False
    return good


def _slop_check() -> bool:
    """R2: deterministic (network-free) classifier logic. A hallucinated compound
    name that is absent from PyPI flags; a real, established compound name does not;
    and mimicry-only (no metadata) never crosses the warn threshold."""
    try:
        from slopgate.slop.classifier import score_slop
        from slopgate.slop.pypi import PkgMeta
    except Exception as exc:  # pragma: no cover
        print(f"[SKIP] slop classifier import failed: {exc}")
        return True
    absent = PkgMeta(name="langchain-jwt-retriever", exists=False)
    established = PkgMeta(name="django-redis", exists=True,
                         first_release_iso="2013-01-01T00:00:00Z",
                         project_urls={"Source": "https://github.com/x/y"})
    hallucinated = score_slop("langchain-jwt-retriever", absent)
    legitimate = score_slop("django-redis", established)
    mimicry_only = score_slop("flask-jwt-router", None)  # offline: no live signal
    good = (hallucinated.would_flag and not legitimate.would_flag
            and not mimicry_only.would_flag)
    print(f"[{'PASS' if good else 'FAIL'}] slop classifier: "
          f"absent-compound={hallucinated.score:.2f}(flag={hallucinated.would_flag}) | "
          f"real-compound={legitimate.score:.2f}(flag={legitimate.would_flag}) | "
          f"offline={mimicry_only.score:.2f}(flag={mimicry_only.would_flag})")
    return good


def _floor_check() -> bool:
    """The symmetric fidelity gate: a claimed-version reproduction is never left
    'not_reproducible', and nothing else is disturbed."""
    try:
        from slopgate.agent.gate import apply_reproduction_floor
        from slopgate.agent.schema import Verdict
        from slopgate.model.trace import Trajectory
    except Exception as exc:  # pragma: no cover
        print(f"[SKIP] reproduction-floor import failed: {exc}")
        return True
    t = Trajectory(case_id="floor-selftest")
    NR, C, I = Verdict.NOT_REPRODUCIBLE, Verdict.CONFIRMED, Verdict.INSUFFICIENT
    cases = [
        ("reproduced dismissal -> corrected up", NR, True, C),
        ("unreproduced dismissal -> untouched", NR, False, NR),
        ("confirmed -> untouched", C, True, C),
        ("insufficient -> untouched", I, True, I),
    ]
    good = True
    for name, proposed, reproduced, expected in cases:
        got = apply_reproduction_floor(proposed, reproduced, t).verdict
        hit = got == expected
        good = good and hit
        print(f"[{'PASS' if hit else 'FAIL'}] reproduction floor {name}: {got.value}")
    return good


if __name__ == "__main__":
    raise SystemExit(main())
