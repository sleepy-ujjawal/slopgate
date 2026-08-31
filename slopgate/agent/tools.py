"""The reproduction tool the triage agent is allowed to call.

This is the only capability that touches the outside world, and it is the only
source of the evidence that can back a 'confirmed' verdict. It wraps the sandbox
runner, records the call on the trajectory, and resolves the human version string
a report uses (e.g. "5.3.1") to a pinned sandbox environment id (e.g. "pyyaml-5.3.1").
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from slopgate.model.trace import Trajectory
from slopgate.sandbox.runner import attempt_reproduction, ReproResult

ENVIRONMENTS_TSV = Path(__file__).resolve().parents[2] / "corpus" / "environments.tsv"


def available_envs() -> list[str]:
    envs = []
    for line in ENVIRONMENTS_TSV.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        envs.append(line.split("\t")[0])
    return envs


def sibling_envs(package: str, exclude: Optional[str] = None) -> list[str]:
    """All sandbox envs for a package, optionally excluding one already tested.

    Used by the version sweep: if a PoC does not fire on the claimed version, the
    same PoC is tried against sibling versions to tell a genuinely-real gadget
    (reproduces somewhere) from an empty claim (reproduces nowhere).
    """
    prefix = f"{package.lower()}-"
    return [e for e in available_envs() if e.startswith(prefix) and e != exclude]


def resolve_env(package: str, version: str) -> Optional[str]:
    """Map (package, version) to a pinned env id, or None if we don't have it.

    Returning None is a real signal, not a failure: if the exact claimed version
    is not in the sandbox, the agent must reason about that (test a neighbour,
    or abstain) rather than silently pretend.
    """
    want = f"{package.lower()}-{version.strip()}"
    envs = available_envs()
    if want in envs:
        return want
    # tolerate a trailing patch-zero mismatch (e.g. "3.1" vs "3.1.0")
    for env in envs:
        if env == want or env.replace(".0", "") == want.replace(".0", ""):
            return env
    return None


def run_reproduction(
    trajectory: Trajectory, *, agent: str, env_id: str, poc_code: str
) -> ReproResult:
    """Execute a PoC in a pre-baked sandbox env and record it on the trajectory."""
    result = attempt_reproduction(env_id, poc_code)
    trajectory.tool_call(
        agent=agent,
        tool="attempt_reproduction",
        args={"env_id": env_id, "poc_code": poc_code},
        result={
            "outcome": result.outcome,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "command": result.command,
        },
    )
    return result


def reproduce_auto(
    trajectory: Trajectory, *, agent: str, package: str, version: str, poc_code: str
):
    """Reproduce against (package, version), pre-baked if available else dynamic.

    Returns an object exposing .outcome, .stdout, .command and
    .confirms_vulnerability() — both ReproResult and DynamicResult qualify — so
    the same agent code works on the fixed corpus and on arbitrary real packages.
    """
    env = resolve_env(package, version)
    if env:
        return run_reproduction(trajectory, agent=agent, env_id=env, poc_code=poc_code)

    # Not pre-baked: provision the real package on demand.
    from slopgate.sandbox.dynamic import attempt_reproduction_dynamic
    result = attempt_reproduction_dynamic(package, version, poc_code)
    trajectory.tool_call(
        agent=agent,
        tool="attempt_reproduction",
        args={"package": package, "version": version, "mode": "dynamic", "poc_code": poc_code},
        result={
            "outcome": result.outcome,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "command": result.command,
        },
    )
    return result
