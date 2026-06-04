"""
Non-blocking warning overlay.

v1: Tkinter banner at the top of the primary screen.  Always on top.
    Auto-dismisses after AUTO_DISMISS_SECS unless the child clicks "Got it".

v2 note (known limitation): upgrading to a PyObjC NSWindow at
NSFloatingWindowLevel with setIgnoresMouseEvents_(True) would give true
click-through so the banner never interrupts game input.  Full-screen game
overlay is also a v2 item.
"""
import tkinter as tk
from tkinter import font as tkfont
from typing import Callable

import mss

AUTO_DISMISS_SECS = 30


def _screen_width() -> int:
    try:
        with mss.mss() as sct:
            return sct.monitors[1]["width"]
    except Exception:
        return 1440


class OverlayBanner:
    """
    A persistent Tkinter root that can show/hide a top-of-screen warning banner.
    Must be driven from the main thread via show() and the Tkinter event loop.
    """

    def __init__(self) -> None:
        self._root = tk.Tk()
        self._root.withdraw()          # hidden until first alert
        self._root.overrideredirect(True)
        self._root.wm_attributes("-topmost", True)
        self._root.wm_attributes("-alpha", 0.93)
        self._root.configure(bg="#E65100")

        self._dismiss_job: str | None = None
        self._build_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        root = self._root
        w = _screen_width()
        root.geometry(f"{w}x110+0+0")

        # left: warning icon block
        icon_frame = tk.Frame(root, bg="#BF360C", width=90)
        icon_frame.pack(side="left", fill="y")
        icon_frame.pack_propagate(False)

        icon_lbl = tk.Label(
            icon_frame, text="⚠", font=("Helvetica", 36, "bold"),
            fg="white", bg="#BF360C",
        )
        icon_lbl.place(relx=0.5, rely=0.5, anchor="center")

        # center: message
        msg_frame = tk.Frame(root, bg="#E65100")
        msg_frame.pack(side="left", fill="both", expand=True, padx=16, pady=8)

        self._headline = tk.Label(
            msg_frame,
            text="This looks like a scam",
            font=("Helvetica", 17, "bold"),
            fg="white", bg="#E65100", anchor="w",
        )
        self._headline.pack(anchor="w")

        self._subtext = tk.Label(
            msg_frame,
            text="",
            font=("Helvetica", 13),
            fg="#FFE0B2", bg="#E65100", anchor="w", wraplength=w - 250,
            justify="left",
        )
        self._subtext.pack(anchor="w", pady=(2, 0))

        self._timer_lbl = tk.Label(
            msg_frame, text="",
            font=("Helvetica", 11), fg="#FFCC80", bg="#E65100", anchor="w",
        )
        self._timer_lbl.pack(anchor="w", pady=(2, 0))

        # right: dismiss button
        btn_frame = tk.Frame(root, bg="#E65100")
        btn_frame.pack(side="right", padx=20)

        btn = tk.Button(
            btn_frame,
            text="Got it — I'll talk to a parent",
            font=("Helvetica", 13, "bold"),
            bg="white", fg="#BF360C",
            relief="flat", padx=12, pady=8,
            cursor="hand2",
            command=self.hide,
        )
        btn.pack()

    # ------------------------------------------------------------------
    # Public API (call from main thread only)
    # ------------------------------------------------------------------

    def show(self, tactic: str, description: str, confidence: float) -> None:
        """Display the banner for the given finding."""
        self._cancel_auto_dismiss()

        conf_pct = int(confidence * 100)
        self._headline.config(text="This looks like a scam — talk to a parent")
        self._subtext.config(
            text=f"Detected: {description}  ({conf_pct}% confidence)"
        )
        self._update_timer(AUTO_DISMISS_SECS)

        self._root.deiconify()
        self._root.lift()

    def hide(self) -> None:
        self._cancel_auto_dismiss()
        self._root.withdraw()

    def after(self, ms: int, fn: Callable, *args) -> str:
        """Proxy to root.after so callers don't need the root reference."""
        return self._root.after(ms, fn, *args)

    def mainloop(self) -> None:
        self._root.mainloop()

    def quit(self) -> None:
        self._root.quit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_timer(self, remaining: int) -> None:
        if remaining <= 0:
            self.hide()
            return
        self._timer_lbl.config(text=f"Auto-dismisses in {remaining}s")
        self._dismiss_job = self._root.after(
            1000, self._update_timer, remaining - 1
        )

    def _cancel_auto_dismiss(self) -> None:
        if self._dismiss_job:
            self._root.after_cancel(self._dismiss_job)
            self._dismiss_job = None
