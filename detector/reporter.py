"""
Optional cloud reporter: sends structured events to the Cloudflare Worker.
Runs in a background thread so it never blocks the detection loop.
If the Worker URL is not configured or the network is unavailable, events
are silently dropped (local log is the source of truth offline).
"""
import json
import threading
import urllib.request
import urllib.error

_UA = "ScamDetector/1.0"


def register_device(worker_url: str, device_token: str, device_name: str = "child's Mac") -> bool:
    """
    POST /register to the Worker so the device is known before events arrive.
    Called once on startup from the main thread (blocks briefly, max 8s).
    Returns True on success or if the device was already registered.
    Fails silently and returns False if offline or Worker URL is unset.
    """
    if not worker_url:
        return False
    url = worker_url.rstrip("/") + "/register"
    data = json.dumps({"token": device_token, "name": device_name}).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": _UA},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read())
            return body.get("ok", False)
    except (urllib.error.URLError, OSError):
        return False


def send_event(event: dict, worker_url: str, device_token: str) -> None:
    """Fire-and-forget POST to the Worker in a daemon thread."""
    if not worker_url:
        return
    thread = threading.Thread(
        target=_post_event,
        args=(event, worker_url, device_token),
        daemon=True,
    )
    thread.start()


def _post_event(event: dict, worker_url: str, device_token: str) -> None:
    url = worker_url.rstrip("/") + "/events"
    data = json.dumps(event).encode()
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
        with urllib.request.urlopen(req, timeout=8) as resp:
            pass  # success
    except (urllib.error.URLError, OSError):
        pass  # offline — local log still has the event
