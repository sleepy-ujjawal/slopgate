"""Python runtime: a thin Runtime wrapper over the existing dynamic provisioner.

The dynamic PyPI provisioning logic is already proven in
`slopgate.sandbox.dynamic`; this just adapts it to the `Runtime` protocol so the
router in `get_runtime` can treat Python like any other ecosystem.
"""
from __future__ import annotations

from slopgate.sandbox.base import RunResult, Target


class PythonRuntime:
    def reproduce(self, target: Target, poc_code: str) -> RunResult:
        from slopgate.sandbox.dynamic import attempt_reproduction_dynamic
        r = attempt_reproduction_dynamic(target.package, target.version, poc_code)
        return RunResult(r.outcome, r.stdout, r.stderr, r.command)
