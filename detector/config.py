"""
Persistent config: device token, optional Worker URL.
Stored in ~/.scam_detector/config.json — never contains raw screen data.
"""
import json
import os
import secrets
import string
from pathlib import Path

CONFIG_DIR = Path.home() / ".scam_detector"
CONFIG_FILE = CONFIG_DIR / "config.json"


def _generate_token() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(12))


def load() -> dict:
    CONFIG_DIR.mkdir(exist_ok=True)
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    cfg = {
        "device_token": _generate_token(),
        "worker_url": "",   # set this to your deployed Worker URL
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
    return cfg


def save(cfg: dict) -> None:
    CONFIG_DIR.mkdir(exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
