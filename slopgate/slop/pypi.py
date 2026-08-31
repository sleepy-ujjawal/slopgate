"""Minimal stdlib PyPI JSON client for the slop classifier.

Stdlib only (urllib), mirroring `slopgate/model/gemini.py`, so a judge can run it
from a clean Python install with no third-party dependencies. Responses are cached
under `realdata/pypicache/<pkg>.json` so the eval is reproducible and does not hammer
pypi.org.

The endpoint `https://pypi.org/pypi/<pkg>/json` yields release upload timestamps
(package age) and `info.project_urls` / `info.home_page` (provenance). It does NOT
report download counts — those require a separate source (pypistats.org) and are
deliberately out of scope here; the temporal vector uses age + release count only.

Failure policy is conservative for a warn-only feature: a 404 is a *fact* (the name
is not on PyPI — the strongest hallucination signal) and is cached as
`exists=False`; any transient/offline failure returns `None`, and the classifier
then degrades to name-structure signals only.
"""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

API = "https://pypi.org/pypi/{pkg}/json"
REQUEST_TIMEOUT_SECONDS = 15
MAX_RETRIES = 3
CACHE_DIR = Path(__file__).resolve().parents[2] / "realdata" / "pypicache"


@dataclass
class PkgMeta:
    name: str
    exists: bool
    first_release_iso: Optional[str] = None
    latest_release_iso: Optional[str] = None
    releases_count: int = 0
    project_urls: Dict[str, str] = field(default_factory=dict)
    home_page: str = ""
    fetched_at: str = ""

    @property
    def has_provenance(self) -> bool:
        return bool(self.project_urls) or bool(self.home_page.strip())

    @property
    def age_days(self) -> Optional[float]:
        dt = _parse_iso(self.first_release_iso) if self.first_release_iso else None
        if dt is None:
            return None
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0


def _parse_iso(value: str) -> Optional[datetime]:
    # PyPI's `upload_time_iso_8601` looks like "2024-05-01T12:00:00.000000Z".
    # datetime.fromisoformat on 3.9 rejects a trailing 'Z', so normalise it.
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _cache_path(package: str) -> Path:
    safe = package.strip().lower().replace("/", "_").replace("\\", "_")
    return CACHE_DIR / f"{safe}.json"


def _read_cache(package: str) -> Optional[PkgMeta]:
    path = _cache_path(package)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return PkgMeta(**data)
    except Exception:
        return None


def _write_cache(meta: PkgMeta) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache_path(meta.name).write_text(
            json.dumps(asdict(meta), indent=2), encoding="utf-8")
    except Exception:
        pass  # caching is best-effort; never fail a lookup over it


def _parse_payload(package: str, payload: dict) -> PkgMeta:
    info = payload.get("info") or {}
    releases = payload.get("releases") or {}
    upload_times = []
    for files in releases.values():
        for f in files or []:
            iso = f.get("upload_time_iso_8601") or f.get("upload_time")
            if iso:
                upload_times.append(iso)
    upload_times.sort()
    project_urls = info.get("project_urls") or {}
    if not isinstance(project_urls, dict):
        project_urls = {}
    return PkgMeta(
        name=package,
        exists=True,
        first_release_iso=upload_times[0] if upload_times else None,
        latest_release_iso=upload_times[-1] if upload_times else None,
        releases_count=sum(1 for v in releases.values() if v),
        project_urls={str(k): str(v) for k, v in project_urls.items()},
        home_page=str(info.get("home_page") or ""),
        fetched_at=datetime.now(timezone.utc).isoformat(),
    )


def _fetch_live(package: str) -> Optional[PkgMeta]:
    url = API.format(pkg=urllib.request.quote(package.strip(), safe=""))
    last_transient = False
    for attempt in range(MAX_RETRIES):
        req = urllib.request.Request(url, headers={"Accept": "application/json"},
                                     method="GET")
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return _parse_payload(package, data)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # Definitive: the name is not published. Cache it as a real fact.
                return PkgMeta(name=package, exists=False,
                               fetched_at=datetime.now(timezone.utc).isoformat())
            last_transient = exc.code >= 500 or exc.code == 429
            if not last_transient:
                return None
        except (urllib.error.URLError, TimeoutError, socket.timeout,
                OSError, json.JSONDecodeError):
            last_transient = True
        if attempt < MAX_RETRIES - 1 and last_transient:
            time.sleep(min(2 ** attempt, 8))
    return None


def fetch_metadata(package: str, *, use_cache: bool = True,
                   force: bool = False) -> Optional[PkgMeta]:
    """Return PyPI metadata for `package`, or None if it could not be fetched.

    `exists=False` in the returned PkgMeta means a confirmed 404 (name not on PyPI);
    a None return means a transient/offline failure (unknown, not a signal).
    """
    if use_cache and not force:
        cached = _read_cache(package)
        if cached is not None:
            return cached
    meta = _fetch_live(package)
    if meta is not None and use_cache:
        _write_cache(meta)
    return meta
