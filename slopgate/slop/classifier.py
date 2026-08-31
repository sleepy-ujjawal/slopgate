"""S_slop: score whether a package NAME looks like AI-hallucinated slop.

This is the R2 fix. It targets the *actual* threat — an LLM inventing a plausible
COMPOUND name (`langchain-chroma-retriever`, `flask-jwt-router`) that an attacker
then registers — rather than near-miss typos of popular packages (Levenshtein edit
distance), which is a different and much narrower threat. Levenshtein is demoted; it
is not used as the primary signal here.

It is **warn-only**. `score_slop` computes a score and a `would_flag` boolean, but
nothing in this module blocks anything. The pipeline attaches the advisory to a memo
that still requires human review, and `slopgate.slop.eval` measures the
false-positive rate against real, recently-published packages — because the vectors
below deliberately correlate with legitimate young packages, and a synchronous block
is indefensible until that FP rate is known.

Vectors and weights (explicit and tunable):

    V_mimicry     0.45  compound [framework]+[domain/utility] name shape
    V_temporal    0.30  package is very young, or absent from PyPI entirely
    V_provenance  0.20  no project URLs / homepage (an owned package usually has one)
    V_context     0.05  diff came from an AI tool

Two deliberate design choices, both from the Round-3 review:
  * The weights are set so V_mimicry ALONE (max 0.45) cannot cross the 0.75 threshold.
    A name only flags when its shape is corroborated by a live registry signal
    (youth / absence / missing provenance). Offline, with no metadata, the classifier
    therefore never flags — the safe direction for warn-only.
  * V_context has near-zero weight on purpose: by 2026 most legitimate PRs are
    AI-assisted, so "touched by an agent" is a tie-breaker, never a driver.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional

from slopgate.slop.pypi import PkgMeta

FRAMEWORK_ROOTS = {
    "langchain", "llama", "llamaindex", "flask", "django", "fastapi", "starlette",
    "pydantic", "boto3", "botocore", "requests", "httpx", "aiohttp", "numpy",
    "pandas", "scipy", "torch", "pytorch", "tensorflow", "keras", "sklearn",
    "scikit", "sqlalchemy", "celery", "pytest", "openai", "anthropic",
    "transformers", "huggingface", "langgraph", "pinecone", "chroma", "weaviate",
}
DOMAIN_TOKENS = {
    "auth", "jwt", "oauth", "aws", "s3", "gcp", "azure", "db", "sql", "redis",
    "kafka", "mongo", "postgres", "xml", "json", "yaml", "csv", "http", "grpc",
    "ssl", "tls", "crypto", "vector", "embedding", "embeddings", "rag", "llm",
}
UTILITY_TOKENS = {
    "client", "server", "router", "retry", "codec", "parser", "wrapper", "helper",
    "helpers", "utils", "util", "toolkit", "sanitizer", "validator", "async",
    "sync", "cache", "middleware", "adapter", "connector", "loader", "exporter",
    "logger", "proxy", "retriever", "runner", "manager", "handler", "sdk",
}

W_MIMICRY = 0.45
W_TEMPORAL = 0.30
W_PROVENANCE = 0.20
W_CONTEXT = 0.05
THRESHOLD = 0.75
YOUNG_DAYS = 30
RECENT_DAYS = 180


@dataclass
class SlopScore:
    package: str
    score: float
    would_flag: bool
    threshold: float
    reason: str
    vectors: Dict[str, float] = field(default_factory=dict)


def _tokens(package: str) -> list:
    return [t for t in re.split(r"[-_.]+", package.strip().lower()) if t]


def _mimicry(tokens: list) -> float:
    """Structural: a framework root followed by domain/utility tokens the framework
    does not own. 1.0 for a full compound, 0.5 for framework + one unrelated token."""
    if len(tokens) < 2 or tokens[0] not in FRAMEWORK_ROOTS:
        return 0.0
    rest = tokens[1:]
    if any(t in DOMAIN_TOKENS or t in UTILITY_TOKENS for t in rest):
        return 1.0
    return 0.5  # compound on a known root, but the extra token isn't a stock filler


def _temporal(meta: Optional[PkgMeta]) -> float:
    if meta is None:
        return 0.0                      # unknown — do not penalise (warn-only)
    if not meta.exists:
        return 1.0                      # not on PyPI at all — purest hallucination signal
    age = meta.age_days
    if age is None:
        return 0.2                      # exists but undatable
    if age < YOUNG_DAYS:
        return 0.7
    if age < RECENT_DAYS:
        return 0.3
    return 0.0


def _provenance(meta: Optional[PkgMeta]) -> float:
    if meta is None or not meta.exists:
        return 0.0                      # temporal already carries the absence signal
    return 0.0 if meta.has_provenance else 1.0


def score_slop(package: str, meta: Optional[PkgMeta],
               ai_authored: bool = False) -> SlopScore:
    tokens = _tokens(package)
    v = {
        "mimicry": _mimicry(tokens),
        "temporal": _temporal(meta),
        "provenance": _provenance(meta),
        "context": 1.0 if ai_authored else 0.0,
    }
    score = (W_MIMICRY * v["mimicry"] + W_TEMPORAL * v["temporal"]
             + W_PROVENANCE * v["provenance"] + W_CONTEXT * v["context"])
    score = round(score, 4)

    reasons = []
    if v["mimicry"] >= 1.0:
        reasons.append("compound framework+domain name shape")
    elif v["mimicry"] > 0:
        reasons.append("compound name on a known framework root")
    if meta is not None and not meta.exists:
        reasons.append("name is not published on PyPI")
    elif v["temporal"] >= 0.7:
        reasons.append("very recently published")
    elif v["temporal"] > 0:
        reasons.append("recently published")
    if v["provenance"] > 0:
        reasons.append("no repository/homepage provenance")
    if v["context"] > 0:
        reasons.append("introduced by an AI-assisted change")

    return SlopScore(
        package=package,
        score=score,
        would_flag=score >= THRESHOLD,
        threshold=THRESHOLD,
        reason="; ".join(reasons) if reasons else "no slop signals",
        vectors=v,
    )
