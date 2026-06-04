"""
Screen capture using mss.  Returns a PIL Image; caller is responsible for
discarding it after OCR — never write raw frames to disk.
"""
from PIL import Image
import mss


_sct = None  # reuse the mss context across captures


def _get_sct():
    global _sct
    if _sct is None:
        _sct = mss.mss()
    return _sct


def grab_primary() -> Image.Image:
    """Capture the primary monitor and return a PIL RGB image."""
    sct = _get_sct()
    monitor = sct.monitors[1]  # primary display
    raw = sct.grab(monitor)
    return Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")


def close() -> None:
    global _sct
    if _sct is not None:
        _sct.close()
        _sct = None
