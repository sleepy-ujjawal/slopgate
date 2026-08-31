"""R1: fail-closed static reachability slicing (prototype-scale).

Public surface:
    classify_reachability(source, target_module, target_symbol) -> ReachResult
    REACHABLE_CONFIRMED / DYNAMIC_AMBIGUOUS / UNREACHABLE_STRICT
"""
from slopgate.reach.slicer import (
    AMBIGUOUS,
    REACHABLE,
    UNREACHABLE,
    ReachResult,
    classify_reachability,
)

__all__ = [
    "classify_reachability",
    "ReachResult",
    "REACHABLE",
    "AMBIGUOUS",
    "UNREACHABLE",
]
