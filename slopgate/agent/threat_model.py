"""Threat-model gate: a reproduction is not a vulnerability if the precondition
is a resource the attacker would only control by already owning the system.

The dominant real-world slop class the corpus turned up is not fabrication — it
is trust-model confusion. dnsmasq, Kamailio, Hibernate, and the `future`
CVE-2025-50817 all describe behaviour that genuinely reproduces, but only after
the attacker replaces a config file, writes to a trusted path, or otherwise
controls something they could not reach without already compromising the host.
Reproduction proves the code runs; it does NOT prove a trust boundary was crossed.

So after a confirmation survives the execution gate, this stage asks one question:
what must the attacker supply or control to trigger this? If the answer is normal
attacker-reachable UNTRUSTED input (a network message, a user-supplied document,
token, archive, or request parameter), the confirmation stands. If the answer is a
TRUSTED resource (a local/server config file, a file on a trusted path, the host
filesystem), the verdict is downgraded to insufficient_evidence and routed to a
human — because "the attacker already owns the box" is not a vulnerability.

Conservatism is deliberate: it downgrades ONLY on a clearly-identified trusted-
resource precondition. On any uncertainty it keeps the confirmation (and flags the
question for the human), so it never quietly discards a real vulnerability. The
identified precondition is emitted as the auditable artifact — the check produces
evidence, not just a verdict.
"""
from __future__ import annotations

from dataclasses import dataclass

from slopgate.agent.llm import ask_json
from slopgate.agent.schema import Report, Verdict
from slopgate.model.trace import Trajectory

AGENT = "threat_model"

SYSTEM = (
    "You are a senior security engineer performing threat-model triage. A "
    "proof-of-concept has already REPRODUCED — the code runs as described. Decide "
    "whether that reproduction crosses a real trust boundary.\n\n"
    "DEFAULT TO untrusted_input. Almost every real vulnerability delivers its "
    "malicious data AS A PAYLOAD — a value passed into the vulnerable function. "
    "That is untrusted_input, EVEN IF the library's documentation says it is "
    "'intended for trusted use' or 'trusted configuration'. The whole point of the "
    "vulnerability is that untrusted data reaches a dangerous sink. Examples that "
    "are ALL untrusted_input:\n"
    "  - a config/data VALUE, dict, or string passed into a function (e.g. a "
    "config object given to instantiate(), a parameter given to a call) — the "
    "attacker supplies the value;\n"
    "  - a deserialized payload (pickle/yaml/jsonpickle) read from a request, "
    "message, or supplied blob;\n"
    "  - an uploaded or downloaded archive, document, image, or template;\n"
    "  - a token or credential the attacker forges and sends.\n\n"
    "Choose trusted_resource ONLY when the trigger literally requires the attacker "
    "to ALREADY have write access to the victim's host — they must OVERWRITE or "
    "PLACE a file on disk that the application then reads as its own trusted "
    "resource. The tell is an explicit step like 'replace /etc/app.conf', 'edit "
    "the server's persistence.xml', or 'write test.py into a directory already on "
    "the import path'. If the malicious data is instead handed to the code as a "
    "value/payload, it is untrusted_input — NOT trusted_resource.\n\n"
    "If you are unsure, choose untrusted_input (never discard a real vulnerability "
    "on a maybe). Reserve trusted_resource for the unambiguous 'attacker must "
    "already own the filesystem' case."
)


@dataclass
class ThreatModelOutcome:
    verdict: Verdict
    downgraded: bool
    precondition: str
    precondition_type: str   # untrusted_input | trusted_resource | unclear
    note: str


def _prompt(report: Report, repro_outcome: str, stdout: str) -> str:
    return (
        f"Report: {report.title}\nPackage: {report.package} {report.affected_version}\n\n"
        f"Report body:\n{report.body[:2500]}\n\n"
        f"Reproduction outcome: {repro_outcome}\nCaptured output:\n{stdout[:1200]}\n\n"
        "Return JSON with keys:\n"
        '  "precondition": one sentence naming exactly what the attacker must '
        "supply or control to trigger this,\n"
        '  "precondition_type": one of "untrusted_input" (attacker-reachable data '
        "through a normal channel), \"trusted_resource\" (a config file / trusted "
        "path / host access the attacker would only have by already owning the "
        'system), or "unclear",\n'
        '  "reasoning": one or two sentences justifying the classification.\n'
        "Only choose trusted_resource when you are confident the trigger needs a "
        "pre-trusted resource; if untrusted input plausibly reaches the sink, "
        'choose "untrusted_input".'
    )


def apply_threat_model_gate(
    report: Report, verdict: Verdict, repro_outcome: str, stdout: str,
    trajectory: Trajectory,
) -> ThreatModelOutcome:
    # Only meaningful for a standing confirmation.
    if verdict != Verdict.CONFIRMED:
        return ThreatModelOutcome(verdict, False, "", "n/a", "")

    data, _ = ask_json(trajectory, agent=AGENT, system=SYSTEM,
                       prompt=_prompt(report, repro_outcome, stdout))
    data = data or {}
    precondition = str(data.get("precondition", "")).strip()
    ptype = str(data.get("precondition_type", "unclear")).strip().lower()
    reasoning = str(data.get("reasoning", "")).strip()

    if ptype == "trusted_resource":
        trajectory.note(
            agent=AGENT,
            message="DOWNGRADED: reproduction requires an attacker-controlled trusted resource",
            data={"precondition": precondition, "reasoning": reasoning})
        return ThreatModelOutcome(
            Verdict.INSUFFICIENT, True, precondition, ptype,
            f"Reproduced, but the trigger requires a trusted resource the attacker "
            f"would only control by already compromising the system: {precondition} "
            f"This is trust-model confusion, not a remotely-reachable vulnerability; "
            f"a human should confirm the deployment's trust boundary.")

    trajectory.note(agent=AGENT, message="threat model upheld confirmation",
                    data={"precondition": precondition, "type": ptype})
    note = ""
    if ptype == "unclear" and precondition:
        note = (f"Attack precondition (verify): {precondition} "
                "Confirmation stands on the reproduction, but the trust boundary "
                "should be checked by a human.")
    return ThreatModelOutcome(verdict, False, precondition, ptype, note)
