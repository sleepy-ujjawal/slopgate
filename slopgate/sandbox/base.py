"""Language-pluggable reproduction runtime.

The Python sandbox proved the model; real reports span other ecosystems (curl is
C). This module is the seam: a `Target` names an (ecosystem, package, version), a
`RunResult` carries the marker-convention outcome, and `get_runtime(ecosystem)`
returns the runner that knows how to provision and execute a PoC for that
language. The Python path keeps its existing implementation in
`slopgate.sandbox.dynamic`; this adds a C/AddressSanitizer runner alongside it.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Target:
    ecosystem: str   # "python" | "c"
    package: str
    version: str


@dataclass
class RunResult:
    outcome: str          # REPRODUCED / NOT_REPRODUCED / ERRORED / INCONCLUSIVE / TIMEOUT / PROVISION_FAILED
    stdout: str
    stderr: str
    command: str

    def confirms_vulnerability(self) -> bool:
        return self.outcome == "REPRODUCED"


def get_runtime(ecosystem: str):
    """Return a runtime with a .reproduce(Target, poc) -> RunResult method."""
    if ecosystem == "c":
        from slopgate.sandbox.c_runtime import CRuntime
        return CRuntime()
    if ecosystem == "python":
        from slopgate.sandbox.python_runtime import PythonRuntime
        return PythonRuntime()
    raise ValueError(f"no runtime for ecosystem {ecosystem!r}")
