"""Independent verifier: re-check each claim against the evidence.

This is the analogue of a systematic review's second independent reviewer. It
does not re-run anything; it reads the report's claims and the reproduction
evidence and rules, per claim, whether the evidence actually supports it. Its
value is catching unsupported assertions that a fluent summary glosses over --
the "structurally plausible, evidence-citing but unsound" failure that the
End-to-End Quality criterion penalises.
"""
from __future__ import annotations

from slopgate.agent.llm import ask_json
from slopgate.agent.schema import Claim, Report
from slopgate.model.trace import Trajectory

AGENT = "verifier"

SYSTEM = (
    "You are an independent verifier. Another engineer has triaged a vulnerability "
    "report and produced claims plus a reproduction result. For EACH claim, decide "
    "whether the reproduction evidence actually supports it. Be strict: a claim is "
    "supported only if the observed output demonstrates it. Narrative confidence is "
    "not evidence. You do not run code; you judge only what is shown."
)


def verify_claims(
    report: Report, claims: list[str], outcome: str, stdout: str, trajectory: Trajectory
) -> list[Claim]:
    if not claims:
        return []
    prompt = (
        f"Report: {report.title} ({report.package} {report.affected_version}).\n"
        f"Reproduction outcome: {outcome}\nCaptured output:\n{stdout[:2000]}\n\n"
        f"Claims to check:\n" + "\n".join(f"{i}. {c}" for i, c in enumerate(claims)) +
        "\n\nReturn JSON: {\"claims\": [{\"index\": int, \"supported\": bool, "
        "\"evidence\": \"one sentence citing the output, or why it is unsupported\"}]}"
    )
    data, _ = ask_json(trajectory, agent=AGENT, system=SYSTEM, prompt=prompt)
    rulings = {r.get("index"): r for r in (data or {}).get("claims", []) if isinstance(r, dict)}

    out: list[Claim] = []
    for i, text in enumerate(claims):
        r = rulings.get(i, {})
        out.append(Claim(
            text=text,
            supported=bool(r.get("supported")) if "supported" in r else None,
            evidence=str(r.get("evidence", "")).strip(),
        ))
    unsupported = sum(1 for c in out if c.supported is False)
    trajectory.note(agent=AGENT, message="verified claims against evidence",
                    data={"total": len(out), "unsupported": unsupported})
    return out
