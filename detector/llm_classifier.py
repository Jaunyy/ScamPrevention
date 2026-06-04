"""
LLM escalation classifier.

Sends a text snippet to the Cloudflare Worker's /classify endpoint,
which proxies to Workers AI (Llama 3.1 8B Instruct).  The Worker holds
the AI binding; no secrets are stored in the Python client.

Privacy: only the minimal text snippet is sent.  It is never logged or
stored locally here.  The Worker does not persist the text either — only
the caller decides whether to log the resulting structured Finding.

Returns (Finding, reasoning_str) so callers can surface the model's one-
sentence explanation in debug output without it leaking into stored events.
"""
from __future__ import annotations
import json
import urllib.request
import urllib.error

from .classifier import Finding, TACTICS

_UA = "ScamDetector/1.0"
_MAX_SNIPPET = 800   # chars forwarded to the model
_TIMEOUT     = 25    # seconds — LLM inference is slower than a DB call


def classify_via_llm(
    text: str,
    worker_url: str,
    device_token: str,
) -> tuple[Finding | None, str]:
    """
    POST a text snippet to Worker /classify.

    Returns:
      (Finding, reasoning) when the model identifies a tactic (confidence > 0)
      (None,    reason)    when model says NONE, parse fails, or offline

    The text is never logged or stored by this function.
    """
    if not worker_url:
        return None, "no worker URL configured"

    url = worker_url.rstrip("/") + "/classify"
    data = json.dumps({"text": text[:_MAX_SNIPPET]}).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {device_token}",
            "User-Agent": _UA,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            body = json.loads(r.read())
    except (urllib.error.URLError, OSError) as exc:
        return None, f"network error: {exc}"

    tactic = body.get("tactic", "NONE")
    reasoning = str(body.get("reasoning", ""))
    raw_conf = body.get("confidence", 0.0)

    if tactic == "NONE" or tactic not in TACTICS:
        return None, reasoning or "NONE"

    try:
        confidence = round(min(1.0, max(0.0, float(raw_conf))), 3)
    except (TypeError, ValueError):
        return None, "bad confidence value"

    if confidence <= 0:
        return None, reasoning or "zero confidence"

    description = TACTICS[tactic].get("description", tactic)
    return Finding(tactic=tactic, confidence=confidence, description=description), reasoning
