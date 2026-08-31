"""Host-side wrapper around the reproduction sandbox.

The agent never invokes Docker directly. It calls attempt_reproduction(), which
returns a structured, tamper-evident record: the exact command, the raw
container output, and a normalized outcome. That record is the *evidence* a
triage memo's "reproduced" claim must be backed by -- the evaluation later
checks that no memo asserts REPRODUCED without a matching record here.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

IMAGE = "slopgate-sandbox:v1"
# Host timeout is shorter than the container's inner ceiling so a wedged
# container is killed from the outside even if the inner guard fails.
HOST_TIMEOUT_SECONDS = 90

VALID_OUTCOMES = {
    "REPRODUCED", "NOT_REPRODUCED", "ERRORED", "INCONCLUSIVE",
    "TIMEOUT", "AMBIGUOUS", "ENV_MISSING", "HOST_TIMEOUT", "HARNESS_ERROR",
}


@dataclass
class ReproResult:
    outcome: str
    env_id: str
    exit_code: Optional[int]
    stdout: str
    stderr: str
    command: str

    def confirms_vulnerability(self) -> bool:
        """The single gate. Only a genuine, observed reproduction counts.

        Every other outcome -- including errors, timeouts, and inconclusive
        runs -- is explicitly NOT a confirmation. This is what stops a
        confidently-worded but non-reproducing report from being signed off.
        """
        return self.outcome == "REPRODUCED"

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


def _to_mount_source(path: Path) -> str:
    """Docker Desktop on Windows wants a Windows-style mount source."""
    try:
        out = subprocess.check_output(["cygpath", "-w", str(path)], text=True).strip()
        return out or str(path)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return str(path)


def attempt_reproduction(env_id: str, poc_code: str) -> ReproResult:
    """Run one proof-of-concept against one pinned environment, in isolation."""
    with tempfile.TemporaryDirectory(prefix="slopgate_poc_") as tmp:
        poc_path = Path(tmp) / "poc.py"
        poc_path.write_text(poc_code, encoding="utf-8")
        mount_src = _to_mount_source(Path(tmp))

        cmd = [
            "docker", "run", "--rm",
            "--network", "none",            # no exfiltration, no silent installs
            "--memory", "512m", "--cpus", "1",
            "--pids-limit", "128",
            "-v", f"{mount_src}:/work:ro",   # PoC is read-only to the container
            IMAGE, env_id, "/work/poc.py",
        ]
        printable = " ".join(cmd)

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=HOST_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return ReproResult("HOST_TIMEOUT", env_id, None, "", "", printable)

        # The container prints one JSON object on stdout; anything else is a
        # harness failure, not a verdict about the report.
        try:
            payload = json.loads(proc.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return ReproResult(
                "HARNESS_ERROR", env_id, proc.returncode,
                proc.stdout[-8000:], proc.stderr[-8000:], printable,
            )

        outcome = payload.get("outcome", "HARNESS_ERROR")
        if outcome not in VALID_OUTCOMES:
            outcome = "HARNESS_ERROR"
        return ReproResult(
            outcome=outcome,
            env_id=payload.get("env_id", env_id),
            exit_code=payload.get("exit_code"),
            stdout=payload.get("stdout", ""),
            stderr=payload.get("stderr", ""),
            command=printable,
        )
