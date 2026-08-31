"""Deterministically construct the evaluation corpus by adversarial injection.

No public benchmark exists for "is this vulnerability report real?", so we build
ground truth ourselves: start from real, historically-accurate advisories with
working proof-of-concept gadgets, then apply named perturbations that turn a
truthful report into a specific kind of slop. Because we author the perturbation,
the label is exactly what we planted — perfect ground truth, tunable difficulty,
and full reproducibility at near-zero data cost.

Each emitted case has two halves:
  * ``report``       — the ONLY thing the agent sees.
  * ``ground_truth`` — expected verdict + the injected-defect name, read solely
                       by the evaluation harness. The harness asserts the agent
                       input never contains these keys (no label leakage).

Run:  python -m slopgate.corpus.build      # (re)writes corpus/cases/*.json
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

CASES_DIR = Path(__file__).resolve().parents[2] / "corpus" / "cases"

# --- Working PoC gadgets, each validated against the sandbox to reproduce on the
#     affected version and NOT reproduce on the patched one. ---------------------

POC_PYYAML = '''\
import os, tempfile, yaml
marker = os.path.join(tempfile.gettempdir(), "m")
if os.path.exists(marker): os.remove(marker)
payload = ('!!python/object/new:type\\n'
           'args: ["z", !!python/tuple [], {"extend": !!python/name:exec }]\\n'
           'listitems: "__import__(\\'os\\').system(\\'touch %s\\')"\\n' % marker)
try:
    yaml.load(payload, Loader=yaml.FullLoader)
except Exception as e:
    print("loader raised:", type(e).__name__)
print("SLOPGATE:REPRODUCED" if os.path.exists(marker) else "SLOPGATE:NOT_REPRODUCED")
'''

POC_JINJA2 = '''\
from jinja2 import Environment
env = Environment()
tmpl = env.from_string("<a {{ mapping|xmlattr }}>")
try:
    out = tmpl.render(mapping={"foo": "bar", "b onmouseover=alert(1) ": "x"})
except Exception as e:
    print("raised:", type(e).__name__); print("SLOPGATE:NOT_REPRODUCED")
else:
    print("RENDER:", out)
    print("SLOPGATE:REPRODUCED" if "onmouseover=alert(1)" in out and " onmouseover" in out
          else "SLOPGATE:NOT_REPRODUCED")
'''

POC_PYJWT = '''\
import jwt
tok = jwt.encode({"admin": True}, "secret", algorithm="HS256")
if isinstance(tok, bytes): tok = tok.decode()
try:
    payload = jwt.decode(tok, "secret")
    print("decoded without algorithms:", payload); print("SLOPGATE:REPRODUCED")
except Exception as e:
    print("raised:", type(e).__name__); print("SLOPGATE:NOT_REPRODUCED")
'''

# A plausible-looking but non-reproducing PoC: it prints scary text and exits 0
# without ever demonstrating the claimed behaviour. This is the shape of a large
# fraction of real AI-generated slop — confident narration, no actual trigger.
POC_FABRICATED = '''\
import yaml  # (import chosen to look on-topic; nothing below proves a vuln)
data = yaml.safe_load("value: 42")
print("Parsed:", data)
print("Analysis indicates the deserializer is exploitable under crafted input.")
# No payload is ever constructed or executed.
'''


@dataclass
class Advisory:
    package: str
    cve: str
    affected_env: str      # env_id where the gadget genuinely reproduces
    patched_env: str       # env_id where it does not
    affected_version: str  # human version string for the affected_env
    patched_version: str
    title: str
    description: str        # the security claim, in a reporter's words
    poc: str
    wrong_function_desc: str  # a claim naming the wrong API, for that perturbation
    fake_vuln_desc: str        # a plausible but FICTIONAL vuln, for fabricated cases


ADVISORIES = [
    Advisory(
        package="PyYAML", cve="CVE-2020-14343",
        affected_env="pyyaml-5.3", patched_env="pyyaml-5.4",
        affected_version="5.3", patched_version="5.4",
        title="Arbitrary code execution via yaml.FullLoader",
        description=(
            "PyYAML's FullLoader still resolves the python/object/new:type tag, so a "
            "crafted document passed to yaml.load(..., Loader=yaml.FullLoader) can "
            "construct arbitrary Python objects and execute code (os.system)."
        ),
        poc=POC_PYYAML,
        wrong_function_desc=(
            "yaml.safe_load() executes embedded Python object tags, allowing remote "
            "code execution when parsing untrusted input."
        ),
        fake_vuln_desc=(
            "PyYAML is vulnerable to a heap buffer overflow in its C-accelerated "
            "scanner when parsing a document with more than 1024 consecutive anchor "
            "aliases, allowing memory corruption and potential RCE via a crafted "
            "YAML file."
        ),
    ),
    Advisory(
        package="Jinja2", cve="CVE-2024-22195",
        affected_env="jinja2-3.1.2", patched_env="jinja2-3.1.3",
        affected_version="3.1.2", patched_version="3.1.3",
        title="HTML attribute injection via the xmlattr filter",
        description=(
            "The xmlattr filter does not reject dictionary keys containing spaces or "
            "quotes, so attacker-controlled keys can inject additional HTML attributes "
            "(e.g. an onmouseover handler), enabling XSS."
        ),
        poc=POC_JINJA2,
        wrong_function_desc=(
            "The tojson filter fails to escape forward slashes, allowing script tag "
            "injection and XSS in rendered templates."
        ),
        fake_vuln_desc=(
            "Jinja2's template cache can be poisoned across requests: rendering a "
            "template whose name contains a null byte causes a later render with a "
            "different name to return the earlier template's output, leaking data "
            "between users."
        ),
    ),
    Advisory(
        package="PyJWT", cve="CVE-2022-29217-adjacent",
        affected_env="pyjwt-1.7.1", patched_env="pyjwt-2.4.0",
        affected_version="1.7.1", patched_version="2.4.0",
        title="jwt.decode accepts tokens without an algorithms restriction",
        description=(
            "jwt.decode() can be called without specifying the algorithms parameter, "
            "so a token is verified without pinning the expected signing algorithm, "
            "opening the door to algorithm-confusion attacks."
        ),
        poc=POC_PYJWT,
        wrong_function_desc=(
            "jwt.encode() defaults to the 'none' algorithm, producing unsigned tokens "
            "that downstream jwt.decode() calls accept as valid."
        ),
        fake_vuln_desc=(
            "PyJWT leaks the HMAC signing key through a timing side channel in its "
            "signature comparison: by measuring jwt.decode() response times an "
            "attacker can recover the secret byte by byte."
        ),
    ),
]


def _report(report_id, package, version, title, body, reporter="anonymous"):
    return {
        "report_id": report_id, "package": package, "affected_version": version,
        "title": title, "body": body, "reporter": reporter,
    }


def _poc_block(poc: str) -> str:
    return f"\n\nProof of concept:\n\n```python\n{poc}```\n"


# --- Perturbations: (advisory) -> (report, ground_truth) ----------------------

def truthful(a: Advisory, idx: int, *, version: str | None = None,
             suffix: str = "", reporter: str = "researcher_a",
             preamble: str | None = None):
    version = version or a.affected_version
    intro = preamble or f"I found a security vulnerability in {a.package} {version}."
    body = (
        f"{intro}\n\n{a.description}\n\nThis is tracked as {a.cve}."
        + _poc_block(a.poc)
    )
    report = _report(f"{a.package.lower()}-truthful{suffix}-{idx}", a.package,
                     version, a.title, body, reporter=reporter)
    gt = {"expected_verdict": "confirmed", "must_reproduce": True,
          "injected_defect": None, "note": "genuine, reproduces on affected version"}
    return report, gt


def version_shift(a: Advisory, idx: int):
    # Same real PoC, but the report claims the ALREADY-PATCHED version is affected.
    body = (
        f"URGENT: {a.package} {a.patched_version} is vulnerable to remote code "
        f"execution / injection.\n\n{a.description}\n\nAffected version: "
        f"{a.patched_version}. Please assign a CVE."
        + _poc_block(a.poc)
    )
    report = _report(f"{a.package.lower()}-vshift-{idx}", a.package,
                     a.patched_version, a.title, body, reporter="bounty_hunter_x")
    gt = {"expected_verdict": "not_reproducible", "must_reproduce": False,
          "injected_defect": "version_shift",
          "note": "PoC is real but the claimed version is already patched"}
    return report, gt


def fabricated_trigger(a: Advisory, idx: int):
    # A FICTIONAL vulnerability that does not exist in the library, reported on a
    # genuinely affected version (so the version string is not the giveaway). No
    # PoC -- however skilfully written -- can reproduce a bug that isn't there.
    # This isolates "confident but false claim" from "can the agent write an exploit".
    body = (
        f"Critical vulnerability in {a.package} {a.affected_version}!!\n\n"
        f"{a.fake_vuln_desc}\n\nI have confirmed this is exploitable in production "
        f"with the help of an AI security assistant. This deserves a maximum "
        f"severity rating and a CVE."
        + _poc_block(POC_FABRICATED)
    )
    fake_title = a.fake_vuln_desc.split(":")[0].split(",")[0][:70]
    report = _report(f"{a.package.lower()}-fabricated-{idx}", a.package,
                     a.affected_version, fake_title, body, reporter="ai_assistant_user")
    gt = {"expected_verdict": "not_reproducible", "must_reproduce": False,
          "injected_defect": "fabricated_trigger",
          "note": "confident prose describing a vulnerability that does not exist"}
    return report, gt


def wrong_function(a: Advisory, idx: int):
    # The narrative names a different API than the real bug; the fabricated PoC
    # does not demonstrate it. Reproduces the 'plausible but misattributed' slop.
    body = (
        f"Security issue in {a.package} {a.affected_version}.\n\n"
        f"{a.wrong_function_desc}\n\nThis is a serious flaw affecting all users."
        + _poc_block(POC_FABRICATED)
    )
    # Title matches the (false) claimed mechanism, not the package's real vuln, so
    # the case cleanly tests a misattributed claim rather than leaking a real one.
    wrong_title = a.wrong_function_desc.split(",")[0].split(".")[0][:70]
    report = _report(f"{a.package.lower()}-wrongfn-{idx}", a.package,
                     a.affected_version, wrong_title, body, reporter="ai_assistant_user")
    gt = {"expected_verdict": "not_reproducible", "must_reproduce": False,
          "injected_defect": "wrong_function",
          "note": "claim names an API that is not where the real behaviour is"}
    return report, gt


def challenging_misversioned(a: Advisory, idx: int):
    # A REAL, working exploit gadget, but the reporter cites a patched version.
    # The honest verdict is abstention: the PoC is a known-good gadget yet does
    # not reproduce as claimed, so it needs a human / a version sweep -- NOT a
    # confident dismissal (false-dismiss) and NOT a confirmation (unsupported).
    body = (
        f"Possible RCE in {a.package} {a.patched_version}.\n\n{a.description}\n\n"
        f"I'm fairly sure this affects {a.patched_version} but I may have the "
        f"version wrong -- can you confirm which releases are impacted?"
        + _poc_block(a.poc)
    )
    report = _report(f"{a.package.lower()}-challenge-{idx}", a.package,
                     a.patched_version, a.title, body, reporter="honest_but_unsure")
    gt = {"expected_verdict": "insufficient_evidence", "must_reproduce": False,
          "injected_defect": "misversioned_real_gadget",
          "note": "real gadget, wrong claimed version -> abstain, do not dismiss"}
    return report, gt


def clean_control_intended_behavior(idx: int):
    # A report that mistakes documented, intended behaviour for a vulnerability.
    body = (
        "Security vulnerability: urllib3 follows HTTP redirects by default.\n\n"
        "When a request receives a 302 response, urllib3 automatically follows it. "
        "An attacker who controls the server can redirect the client to an internal "
        "address. This is a serious SSRF vulnerability affecting urllib3 1.26.4.\n\n"
        "Proof of concept:\n\n```python\n"
        "import urllib3\n"
        "http = urllib3.PoolManager()\n"
        "# (describes default redirect-following; this is documented behaviour,\n"
        "#  configurable via redirect=False, not a vulnerability)\n"
        "print('urllib3 follows redirects by default')\n"
        "print('SLOPGATE:NOT_REPRODUCED')\n"
        "```\n"
    )
    report = _report(f"urllib3-control-{idx}", "urllib3", "1.26.4",
                     "SSRF via automatic redirect following", body, reporter="new_reporter")
    gt = {"expected_verdict": "not_reproducible", "must_reproduce": False,
          "injected_defect": "intended_behavior_as_vuln",
          "note": "documented, configurable default behaviour, not a vuln"}
    return report, gt


def build() -> list[Path]:
    CASES_DIR.mkdir(parents=True, exist_ok=True)
    for old in CASES_DIR.glob("*.json"):
        old.unlink()

    cases = []
    for i, adv in enumerate(ADVISORIES):
        cases.append(truthful(adv, i))
        cases.append(version_shift(adv, i))
        cases.append(fabricated_trigger(adv, i))
    # one wrong-function and one challenging, drawn from distinct families
    cases.append(wrong_function(ADVISORIES[1], 0))          # Jinja2
    cases.append(challenging_misversioned(ADVISORIES[0], 0))  # PyYAML (the hard case)
    cases.append(clean_control_intended_behavior(0))
    cases.append(clean_control_intended_behavior(1))

    # Extra truthful variants so the "confirmed" class is large enough to give
    # the false-dismiss metric usable resolution. Same real vulns, different
    # reporters/versions -- still genuine reproductions.
    cases.append(truthful(ADVISORIES[0], 1, version="5.3.1", suffix="b",
                          reporter="researcher_c",
                          preamble="Reporting a deserialization RCE in PyYAML 5.3.1."))
    cases.append(truthful(ADVISORIES[1], 1, suffix="b", reporter="researcher_d",
                          preamble="xmlattr in Jinja2 3.1.2 lets me inject HTML attributes."))

    written = []
    for report, gt in cases:
        # Leakage guard: the agent-visible report must not carry any label field.
        assert set(report) & set(gt) == set(), "ground-truth key leaked into report"
        case = {"report": report, "ground_truth": gt}
        path = CASES_DIR / f"{report['report_id']}.json"
        path.write_text(json.dumps(case, indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(path)
    return written


if __name__ == "__main__":
    paths = build()
    print(f"Wrote {len(paths)} cases to {CASES_DIR}")
    from collections import Counter
    dist = Counter()
    for p in paths:
        gt = json.loads(p.read_text(encoding="utf-8"))["ground_truth"]
        dist[gt["expected_verdict"]] += 1
    print("verdict distribution:", dict(dist))
