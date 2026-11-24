import json
import os
import re

ID_PATTERN = re.compile(r"\b(GHSA-[\w-]{14}|CVE-\d{4}-\d{4,}|SC-\d{3})\b")
PKG_VERSION_PATTERN = re.compile(r"((?:@[\w.-]+/)?[\w.-]+)@(\d+\.\d+\.\d+[\w.-]*)")

SYSTEM = (
    "You write the final security report of a software supply chain guardian. "
    "You receive JSON evidence produced by real tools (lockfile parser, Syft, OSV-Scanner/npm audit, git diff). "
    "Explain the evidence for an engineering audience. Rules: only mention vulnerability IDs, finding IDs, "
    "package names, versions and dependency paths that appear in the evidence. Never invent CVEs or versions. "
    "If something is not in the evidence, say it is unknown. "
    "Use short markdown sections."
)


def available() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY"))


def ask(evidence: dict, question: str) -> str:
    from anthropic import Anthropic
    client = Anthropic()
    msg = client.messages.create(
        model=os.getenv("GUARDIAN_MODEL", "claude-sonnet-5-5"), max_tokens=1500, system=SYSTEM,
        messages=[{"role": "user", "content": f"EVIDENCE:\n{json.dumps(evidence)}\n\nTASK: {question}"}])
    return "".join(b.text for b in msg.content if b.type == "text")


def unsupported_claims(text: str, evidence: dict) -> list[str]:
    blob = json.dumps(evidence)
    bad = [i for i in set(ID_PATTERN.findall(text)) if i not in blob]
    for name, version in set(PKG_VERSION_PATTERN.findall(text)):
        if version not in blob or name not in blob:
            bad.append(f"{name}@{version}")
    return sorted(bad)


def interpret(evidence: dict, question: str, fallback: str) -> dict:
    """Ask the LLM; reject the answer if it mentions IDs/versions not present in the evidence."""
    if not available():
        return {"text": fallback, "source": "deterministic template (no ANTHROPIC_API_KEY set)"}
    try:
        text = ask(evidence, question)
    except Exception as err:  # network/auth/model errors should not break the scan
        return {"text": fallback, "source": f"deterministic template (LLM error: {err})"}
    bad = unsupported_claims(text, evidence)
    if bad:
        return {"text": fallback, "source": f"deterministic template (LLM output rejected, unsupported: {bad[:5]})"}
    return {"text": text, "source": f"LLM ({os.getenv('GUARDIAN_MODEL', 'claude-sonnet-5-5')}), grounded-check passed"}
