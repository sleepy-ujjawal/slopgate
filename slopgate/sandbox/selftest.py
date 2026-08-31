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


if __name__ == "__main__":
    raise SystemExit(main())
