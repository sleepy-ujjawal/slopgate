"""Runs a single reproduction attempt inside the sandbox container.

Contract with the proof-of-concept script:
    A PoC declares its own outcome by printing one of two sentinels. Relying on
    the exit code alone would conflate "the vulnerability did not reproduce"
    with "the PoC itself is broken" -- a distinction this project's evaluation
    depends on, because a crashed PoC is not evidence that a report is false.

        SLOPGATE:REPRODUCED     the claimed behaviour was observed
        SLOPGATE:NOT_REPRODUCED the claim was tested and did not hold

    A PoC that prints neither and exits non-zero is classified ERRORED, and a
    PoC that prints neither and exits zero is classified INCONCLUSIVE. Neither
    may be reported to a maintainer as a finding.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPRODUCED = "SLOPGATE:REPRODUCED"
NOT_REPRODUCED = "SLOPGATE:NOT_REPRODUCED"

ENVS_ROOT = Path("/envs")
# Hard ceiling inside the container. The host applies its own, shorter timeout;
# this one exists so the container still self-terminates if invoked directly.
INNER_TIMEOUT_SECONDS = 60


def classify(stdout: str, exit_code: int, timed_out: bool) -> str:
    if timed_out:
        return "TIMEOUT"
    saw_repro = REPRODUCED in stdout
    saw_not_repro = NOT_REPRODUCED in stdout
    if saw_repro and saw_not_repro:
        # An honest harness refuses to guess which the author meant.
        return "AMBIGUOUS"
    if saw_repro:
        return "REPRODUCED"
    if saw_not_repro:
        return "NOT_REPRODUCED"
    return "ERRORED" if exit_code != 0 else "INCONCLUSIVE"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: entrypoint.py <env_id> <poc_path>", file=sys.stderr)
        return 2

    env_id, poc_path = sys.argv[1], sys.argv[2]
    env_dir = ENVS_ROOT / env_id

    if not env_dir.is_dir():
        available = sorted(p.name for p in ENVS_ROOT.iterdir()) if ENVS_ROOT.is_dir() else []
        print(json.dumps({
            "outcome": "ENV_MISSING",
            "env_id": env_id,
            "available_envs": available,
        }))
        return 3

    # PYTHONPATH is the only thing that differs between environments, so a
    # reproduction attempt is pinned to exactly the version the report names.
    child_env = dict(os.environ, PYTHONPATH=str(env_dir))

    timed_out = False
    try:
        proc = subprocess.run(
            [sys.executable, poc_path],
            capture_output=True,
            text=True,
            timeout=INNER_TIMEOUT_SECONDS,
            env=child_env,
            cwd="/work",
        )
        stdout, stderr, exit_code = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        exit_code = -1

    print(json.dumps({
        "outcome": classify(stdout, exit_code, timed_out),
        "env_id": env_id,
        "exit_code": exit_code,
        "stdout": stdout[-8000:],
        "stderr": stderr[-8000:],
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
