"""LLM reasoning for Day 2, with guard rails.

* The LLM only explains evidence the agents already verified. It never adds findings.
* Each answer is checked: any advisory id, finding id or package@version it mentions must appear in
  that item's evidence. Answers that fail are discarded and the rule-based explanation is used.
* Every prompt and response is logged to day2/llm_log.jsonl (no secrets are sent: only package
  names, versions, advisory text and file excerpts from the repository and public registries).
* Providers: Groq (GROQ_API_KEY), Anthropic (ANTHROPIC_API_KEY), or any OpenAI-compatible endpoint, e.g. OpenRouter
  or a local Ollama (GUARDIAN_LLM_BASE_URL + GUARDIAN_LLM_API_KEY + GUARDIAN_LLM_MODEL).
  With neither configured the Guardian still works, using rule-based reasoning that is labelled as such.
"""
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

from guardian.day2.common import day2_dir, now
from guardian.llm import unsupported_claims

SYSTEM = (
    "You are the reasoning module of a software supply chain security tool. You receive EVIDENCE that real tools "
    "verified (lockfile, npm registry metadata, vulnerability databases, git history, source-code imports). "
    "For each item, write the requested explanation for an engineer in 2-4 plain sentences. Rules: use only facts "
    "in that item's evidence; never invent advisory ids, versions, files or exploits; if something is unknown say so; "
    "do not repeat the numbers table, explain what they mean. Reply with ONLY a JSON object mapping each item id to "
    "its explanation string."
)


def provider() -> dict | None:
    if os.getenv("GUARDIAN_LLM_DISABLED"):
        return None
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        return {"kind": "groq", "base": "https://api.groq.com/openai/v1", "key": groq_key,
                "model": os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")}
    if os.getenv("ANTHROPIC_API_KEY"):
        return {"kind": "anthropic", "model": os.getenv("GUARDIAN_MODEL", "claude-sonnet-5-5")}
    base = os.getenv("GUARDIAN_LLM_BASE_URL")
    if base:
        return {"kind": "openai", "base": base.rstrip("/"), "key": os.getenv("GUARDIAN_LLM_API_KEY", ""),
                "model": os.getenv("GUARDIAN_LLM_MODEL", "llama-3.3-70b-versatile")}
    return None


def describe_provider() -> str:
    p = provider()
    if not p:
        return "rule-based (no LLM configured)"
    name = {"anthropic": "Anthropic", "groq": "Groq"}.get(p["kind"]) or p["base"]
    return f"{p['model']} via {name}"


def _call(p: dict, prompt: str) -> str:
    if p["kind"] == "anthropic":
        from anthropic import Anthropic
        msg = Anthropic().messages.create(model=p["model"], max_tokens=4000, system=SYSTEM,
                                          messages=[{"role": "user", "content": prompt}])
        return "".join(b.text for b in msg.content if b.type == "text")
    token_limit = "max_completion_tokens" if p["kind"] == "groq" else "max_tokens"
    body = json.dumps({"model": p["model"], "temperature": 0.1, token_limit: 4000, "messages": [
        {"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]}).encode("utf-8")
    # a browser-like User-Agent: some API gateways (Cloudflare) reject Python's default one with 403
    req = urllib.request.Request(p["base"] + "/chat/completions", data=body, headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {p['key']}",
        "User-Agent": "Mozilla/5.0 (software-supply-chain-guardian)"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                msg = json.loads(r.read().decode("utf-8"))["choices"][0]["message"]
                return msg.get("content") or ""
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:300]
            if e.code == 429 and attempt < 3:  # rate limit: wait as asked, then retry
                time.sleep(min(float(e.headers.get("retry-after") or 8), 30))
                continue
            raise RuntimeError(f"HTTP {e.code}: {detail}") from None
    raise RuntimeError("rate limited")


def _parse(text: str) -> dict:
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return {}
    try:
        data = json.loads(m.group(0))
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


CHUNK = int(os.getenv("GUARDIAN_LLM_BATCH", "4"))  # items per request: small enough for free-tier token limits


def _compact(ev, depth=0):
    """Trim long lists and strings so each request stays small; ids and versions are kept."""
    if isinstance(ev, dict):
        return {k: _compact(v, depth + 1) for k, v in ev.items() if v not in (None, [], {}, "")}
    if isinstance(ev, list):
        return [_compact(v, depth + 1) for v in ev[:6]]
    if isinstance(ev, str) and len(ev) > 300:
        return ev[:300] + "…"
    return ev


def explain(out: Path, task: str, items: list[dict], fallback: dict) -> dict:
    """Run in small batches; each batch is checked and logged on its own."""
    result = {}
    for i in range(0, len(items), CHUNK):
        result.update(_explain(out, task, items[i:i + CHUNK], fallback))
    return result


def _explain(out: Path, task: str, items: list[dict], fallback: dict) -> dict:
    """items: [{"id": ..., "evidence": {...}}]; fallback: {id: rule-based text}.
    Returns {id: {"text", "source", "rejected": [...]}}."""
    result = {i["id"]: {"text": fallback.get(i["id"], ""), "source": "rule-based reasoning (no LLM)", "rejected": []}
              for i in items}
    p = provider()
    if not p or not items:
        return result
    prompt = f"TASK: {task}\n\nITEMS:\n" + json.dumps([{"id": i["id"], "evidence": _compact(i["evidence"])} for i in items],
                                                     separators=(",", ":"), default=str)
    log = day2_dir(out) / "llm_log.jsonl"
    try:
        raw = _call(p, prompt)
    except Exception as err:
        for v in result.values():
            v["source"] = f"rule-based reasoning (LLM call failed: {str(err)[:80]})"
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"at": now(), "task": task, "model": p["model"], "error": str(err)[:500]}) + "\n")
        return result
    answers = _parse(raw)
    label = f"AI inference ({p['model']}), grounding check passed"
    for item in items:
        text = answers.get(item["id"])
        if not text:
            continue
        bad = unsupported_claims(text, item["evidence"])
        if bad:
            result[item["id"]]["rejected"] = bad
            result[item["id"]]["source"] = f"rule-based reasoning (AI answer rejected: mentioned {', '.join(bad[:3])} not in evidence)"
        else:
            result[item["id"]] = {"text": text.strip(), "source": label, "rejected": []}
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"at": now(), "task": task, "model": p["model"], "prompt": prompt[:60000],
                             "response": raw[:60000],
                             "accepted": [k for k, v in result.items() if v["source"] == label]}) + "\n")
    return result


if __name__ == "__main__":  # python -m guardian.day2.reasoning  -> checks the LLM connection
    p = provider()
    print("Provider:", describe_provider())
    if not p:
        print("No LLM configured. Set GROQ_API_KEY, ANTHROPIC_API_KEY, or GUARDIAN_LLM_BASE_URL with its key and model.")
    else:
        try:
            print("Reply:", _call(p, 'Reply with only this JSON: {"ok": "connected"}')[:200])
        except Exception as err:
            print("FAILED:", err)
