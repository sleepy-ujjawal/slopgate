"""C runtime: compile a PoC with AddressSanitizer and let a real memory bug crash.

For C the marker convention is not enough on its own — a buffer overflow does not
politely print a sentinel, it corrupts memory. So the PoC is compiled with
`-fsanitize=address` and a genuine memory-safety violation makes ASAN abort with a
recognisable signature (heap/stack-buffer-overflow, use-after-free). A fabricated
bug (the shape of most AI-slop C reports) simply runs clean.

Classification:
  * ASAN error signature in output, OR an explicit SLOPGATE:REPRODUCED  -> REPRODUCED
  * SLOPGATE:NOT_REPRODUCED, or a clean run with no ASAN error           -> NOT_REPRODUCED
  * the PoC fails to compile                                             -> PROVISION_FAILED

The container is network-isolated, non-root, resource-capped, and mounts the PoC
read-only — the same hardening as the Python sandbox. libcurl headers are present
so a PoC that links libcurl (`#include <curl/curl.h>`) compiles with -lcurl.
"""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from slopgate.sandbox.base import RunResult, Target

IMAGE = "slopgate-c-sandbox:v1"
TIMEOUT = 60  # bound a synthesized PoC that loops; compile+run of a real PoC is seconds
ASAN_SIGNATURES = (
    "AddressSanitizer: heap-buffer-overflow",
    "AddressSanitizer: stack-buffer-overflow",
    "AddressSanitizer: global-buffer-overflow",
    "AddressSanitizer: heap-use-after-free",
    "AddressSanitizer: stack-use-after-return",
    "AddressSanitizer: SEGV",
    "runtime error:",  # UBSan-style, if -fsanitize=undefined is ever added
)


def _win(path: Path) -> str:
    try:
        return subprocess.check_output(["cygpath", "-w", str(path)], text=True).strip() or str(path)
    except Exception:
        return str(path)


def _classify(out: str, timed_out: bool, compiled: bool) -> str:
    if not compiled:
        return "PROVISION_FAILED"
    if timed_out:
        return "TIMEOUT"
    if any(sig in out for sig in ASAN_SIGNATURES) or "SLOPGATE:REPRODUCED" in out:
        return "REPRODUCED"
    if "SLOPGATE:NOT_REPRODUCED" in out:
        return "NOT_REPRODUCED"
    # compiled and ran clean with no sanitizer error and no marker: the claimed
    # memory violation did not occur.
    return "NOT_REPRODUCED"


class CRuntime:
    def reproduce(self, target: Target, poc_code: str) -> RunResult:
        with tempfile.TemporaryDirectory(prefix="slopgate_c_") as tmp:
            (Path(tmp) / "poc.c").write_text(poc_code, encoding="utf-8")
            link_curl = "-lcurl" if "curl/curl.h" in poc_code else ""
            # compile to a writable in-container path, then run under ASAN.
            build_run = (
                f"gcc -fsanitize=address -g -O0 /src/poc.c -o /tmp/poc {link_curl} "
                "2>/tmp/cc.err || { echo SLOPGATE_COMPILE_FAILED; cat /tmp/cc.err; exit 7; }; "
                "ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 /tmp/poc 2>&1 || true"
            )
            cmd = [
                "docker", "run", "--rm", "--network", "none",
                "--memory", "512m", "--cpus", "1", "--pids-limit", "256",
                "--user", "1000:1000",
                "-v", f"{_win(Path(tmp))}:/src:ro",
                IMAGE, "sh", "-c", build_run,
            ]
            printable = " ".join(cmd[:-1]) + " '<build+run>'"
            timed_out = False
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      encoding="utf-8", errors="replace", timeout=TIMEOUT)
                out = (proc.stdout or "") + (proc.stderr or "")
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                out = ((exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes)
                       else (exc.stdout or "")) + ((exc.stderr or b"").decode("utf-8", "replace")
                       if isinstance(exc.stderr, bytes) else (exc.stderr or ""))

            compiled = "SLOPGATE_COMPILE_FAILED" not in out
            outcome = _classify(out, timed_out, compiled)
            return RunResult(outcome, out[-8000:], "", printable)
