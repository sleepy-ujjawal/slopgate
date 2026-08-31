"""Dynamic environment provisioning for real-world advisories.

The pre-baked sandbox (environments.tsv) is fine for a fixed corpus, but real
reports name arbitrary packages and versions. This module provisions a
(package, version) on demand:

  1. BUILD phase  — a throwaway python:3.11-slim container WITH network runs
     `pip install --target /out pkg==ver`, writing the dependency tree to a
     host cache directory. This is the only step that touches the network.
  2. EXEC phase   — the same image with `--network none` mounts that cache
     read-only and runs the PoC against exactly that version.

Provisioning is cached by (package, version) so repeated runs are fast. Packages
that need a compiler (C extensions) may fail to build on slim; that is reported
as a provisioning failure, not a reproduction result.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

IMAGE = "python:3.11-slim"
CACHE_ROOT = Path(__file__).resolve().parents[2] / "realdata" / "envcache"
BUILD_TIMEOUT = 300
EXEC_TIMEOUT = 90
REPRODUCED = "SLOPGATE:REPRODUCED"
NOT_REPRODUCED = "SLOPGATE:NOT_REPRODUCED"

_SAFE = re.compile(r"[^A-Za-z0-9._-]")


@dataclass
class DynamicResult:
    outcome: str          # REPRODUCED / NOT_REPRODUCED / ERRORED / INCONCLUSIVE / TIMEOUT / PROVISION_FAILED
    package: str
    version: str
    stdout: str
    stderr: str
    command: str

    def confirms_vulnerability(self) -> bool:
        return self.outcome == "REPRODUCED"


def _key(package: str, version: str) -> str:
    slug = f"{_SAFE.sub('-', package.lower())}-{_SAFE.sub('-', version)}"
    return slug[:60] + "-" + hashlib.sha1(f"{package}=={version}".encode()).hexdigest()[:8]


def _win(path: Path) -> str:
    try:
        return subprocess.check_output(["cygpath", "-w", str(path)], text=True).strip() or str(path)
    except Exception:
        return str(path)


def provision(package: str, version: str) -> tuple[bool, str, Path]:
    """Install (package, version) into a host cache dir. Returns (ok, log, dir)."""
    dest = CACHE_ROOT / _key(package, version)
    dest.mkdir(parents=True, exist_ok=True)
    if (dest / ".provisioned").exists():
        return True, "cached", dest

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{_win(dest)}:/out",
        IMAGE, "pip", "install", "--no-cache-dir", "--target", "/out",
        f"{package}=={version}",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=BUILD_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False, "provision timeout", dest
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout)[-1500:], dest
    (dest / ".provisioned").write_text("ok", encoding="utf-8")
    return True, "installed", dest


def _classify(stdout: str, code: int, timed_out: bool) -> str:
    if timed_out:
        return "TIMEOUT"
    if REPRODUCED in stdout and NOT_REPRODUCED in stdout:
        return "AMBIGUOUS"
    if REPRODUCED in stdout:
        return "REPRODUCED"
    if NOT_REPRODUCED in stdout:
        return "NOT_REPRODUCED"
    return "ERRORED" if code != 0 else "INCONCLUSIVE"


def attempt_reproduction_dynamic(package: str, version: str, poc_code: str) -> DynamicResult:
    ok, log, dest = provision(package, version)
    if not ok:
        return DynamicResult("PROVISION_FAILED", package, version, "", log,
                             f"pip install {package}=={version}")

    import tempfile
    with tempfile.TemporaryDirectory(prefix="slopgate_dyn_") as tmp:
        poc = Path(tmp) / "poc.py"
        poc.write_text(poc_code, encoding="utf-8")
        cmd = [
            "docker", "run", "--rm", "--network", "none",
            "--memory", "512m", "--cpus", "1", "--pids-limit", "256",
            "-e", "PYTHONPATH=/deps",
            "-v", f"{_win(dest)}:/deps:ro",
            "-v", f"{_win(Path(tmp))}:/work:ro",
            IMAGE, "python", "/work/poc.py",
        ]
        printable = " ".join(cmd)
        timed_out = False
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=EXEC_TIMEOUT)
            out, err, code = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            out = (exc.stdout or b"").decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = (exc.stderr or b"").decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            code = -1
        return DynamicResult(_classify(out, code, timed_out), package, version,
                             out[-8000:], err[-8000:], printable)


if __name__ == "__main__":
    import sys
    pkg, ver = sys.argv[1], sys.argv[2]
    poc = sys.stdin.read()
    r = attempt_reproduction_dynamic(pkg, ver, poc)
    print(json.dumps({"outcome": r.outcome, "stdout": r.stdout[-500:], "stderr": r.stderr[-300:]}, indent=2))
