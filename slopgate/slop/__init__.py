"""R2: warn-only AI-slop package-name classifier.

Public surface:
    fetch_metadata(package) -> Optional[PkgMeta]        (slopgate.slop.pypi)
    score_slop(package, meta) -> SlopScore              (slopgate.slop.classifier)
    apply_slop_advisory(report, trajectory) -> SlopOutcome  (slopgate.slop.advisory)
"""
from slopgate.slop.classifier import SlopScore, score_slop
from slopgate.slop.pypi import PkgMeta, fetch_metadata

__all__ = ["fetch_metadata", "PkgMeta", "score_slop", "SlopScore"]
