"""
Structured event logger.  Writes JSONL to ~/.scam_detector/events.jsonl.
Never stores raw OCR text — only tactic type, confidence, and timestamp.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path.home() / ".scam_detector" / "events.jsonl"


def _ensure_dir() -> None:
    LOG_FILE.parent.mkdir(exist_ok=True)


def log_event(tactic: str, confidence: float, extra: dict | None = None) -> dict:
    """
    Append a structured event to the local log and return the event dict.
    extra may contain non-sensitive fields (e.g. game_hint).
    """
    _ensure_dir()
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tactic": tactic,
        "confidence": round(confidence, 3),
    }
    if extra:
        event.update({k: v for k, v in extra.items()})

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

    return event


def recent_events(n: int = 50) -> list[dict]:
    """Return the last n events from the local log."""
    _ensure_dir()
    if not LOG_FILE.exists():
        return []
    lines = LOG_FILE.read_text().strip().splitlines()
    return [json.loads(l) for l in lines[-n:] if l.strip()]
