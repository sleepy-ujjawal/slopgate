# Build log

## Gate 0 (riskiest-step-first): containerized reproduction — PASSED

- Base image `python:3.9-slim`; 12 pinned (package, version) environments spanning
  four CVEs across vulnerable/patched boundaries (`corpus/environments.tsv`).
- Isolation: `--network none`, non-root `runner` user, `--memory 512m --cpus 1`,
  `--pids-limit 128`, PoC mounted read-only. All dependencies installed at build
  time so a run can never fetch a different version than the one under test.
- Outcome contract: PoC prints `SLOPGATE:REPRODUCED` / `SLOPGATE:NOT_REPRODUCED`;
  a crashed PoC is ERRORED (NOT a false-report signal), a silent one INCONCLUSIVE.
- Verified discrimination (CVE-2020-14343, type/extend/exec gadget):
  5.3 ✅ REPRODUCED · 5.3.1 ✅ REPRODUCED · 5.4 ✅ NOT_REPRODUCED · 6.0.1 ✅ NOT_REPRODUCED
- Latency ~1.0s/run (median of 3); image 200MB. 15-case eval → seconds, cents.

### Windows/Git-Bash gotcha (fixed)
MSYS rewrote the `/work/poc.py` container argument into a Windows path. The
host runner normalizes the mount source via `cygpath -w` and avoids passing
MSYS-convertible container paths through the shell. Reproducible off Git Bash.

## Next
1. Agent v0 = single-prompt baseline (verdict from report text alone) — freeze it.
2. Memo schema (verdict / per-claim evidence / reproduction record / abstention / sign-off).
3. Eval harness: real-reproduce cases + injected perturbations + clean controls.
4. Metrics: correct-verdict rate (false-confirm & false-dismiss split) + execution-fidelity.
