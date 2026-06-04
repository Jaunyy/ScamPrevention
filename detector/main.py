"""
Main detector loop.

Architecture:
  - Main thread  : Tkinter event loop (overlay)
  - Worker thread: capture → OCR → classify → queue findings
  - root.after() : drains queue and calls overlay.show() on each finding

The worker thread only sends findings (tactic + confidence) to the main
thread — raw OCR text never crosses the thread boundary.
"""
import queue
import threading
import time
import sys
from pathlib import Path

from . import capture, ocr, classifier, event_log, reporter, config
from .classifier import Finding
from .overlay import OverlayBanner

CAPTURE_INTERVAL = 2.0          # seconds between screen grabs
MIN_TEXT_LENGTH = 15            # ignore frames with almost no text
QUEUE_POLL_MS = 150             # how often the main thread checks the queue


def _detection_worker(
    finding_queue: queue.Queue,
    stop_event: threading.Event,
    debug: bool = False,
) -> None:
    """
    Runs in a daemon thread.  Captures screen, OCRs, classifies, and pushes
    Finding objects into finding_queue.  Raw text is discarded after classify().
    """
    cycle = 0
    while not stop_event.is_set():
        cycle += 1
        try:
            img = capture.grab_primary()
            text = ocr.extract_text(img)
            img.close()          # explicitly release memory

            if debug:
                stripped = text.strip()
                char_count = len(stripped)
                preview = stripped[:300].replace("\n", "↵") if stripped else "(empty)"
                sys.stdout.write(
                    f"\n[debug #{cycle}] OCR extracted {char_count} chars:\n"
                    f"  {preview}"
                    + (" …" if char_count > 300 else "")
                    + "\n"
                )
                sys.stdout.flush()

            if len(text.strip()) >= MIN_TEXT_LENGTH:
                findings = classifier.classify(text)
                if debug and findings:
                    for f in findings:
                        sys.stdout.write(
                            f"  [debug] classifier hit: {f.tactic} @ {f.confidence:.2f}\n"
                        )
                    sys.stdout.flush()
                for f in findings:
                    finding_queue.put_nowait(f)

        except Exception as e:
            # never crash the loop on transient errors
            sys.stderr.write(f"[detector] loop error: {e}\n")

        stop_event.wait(CAPTURE_INTERVAL)

    capture.close()


def run(debug: bool = False) -> None:
    cfg = config.load()
    device_token = cfg["device_token"]
    worker_url = cfg.get("worker_url", "")

    print(f"Scam Coercion Detector starting.")
    print(f"Device token (share with parent dashboard): {device_token}")
    print(f"Worker URL: {worker_url or '(not configured — offline mode)'}")

    if worker_url:
        ok = reporter.register_device(worker_url, device_token)
        if ok:
            print("Cloud: device registered with Worker.")
        else:
            print("Cloud: registration failed (offline?) — running in offline mode.")

    print("Press Ctrl+C to stop.\n")

    finding_queue: queue.Queue[Finding] = queue.Queue()
    stop_event = threading.Event()

    # Start detection worker thread
    worker = threading.Thread(
        target=_detection_worker,
        args=(finding_queue, stop_event, debug),
        daemon=True,
    )
    worker.start()

    # Build overlay (must happen on main thread)
    overlay = OverlayBanner()

    def poll_queue() -> None:
        # Drain all pending findings; show overlay for the highest-confidence one
        findings: list[Finding] = []
        while True:
            try:
                findings.append(finding_queue.get_nowait())
            except queue.Empty:
                break

        if findings:
            # Sort by confidence; show only the top finding per poll cycle
            best = max(findings, key=lambda f: f.confidence)
            print(f"[alert] {best.tactic} confidence={best.confidence:.2f} — {best.description}")

            event = event_log.log_event(
                tactic=best.tactic,
                confidence=best.confidence,
            )
            reporter.send_event(event, worker_url, device_token)
            overlay.show(best.tactic, best.description, best.confidence)

        overlay.after(QUEUE_POLL_MS, poll_queue)

    overlay.after(QUEUE_POLL_MS, poll_queue)

    try:
        overlay.mainloop()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        print("\nDetector stopped.")


if __name__ == "__main__":
    run()
