"""
Main detector loop.

Architecture:
  - Main thread  : Tkinter event loop (overlay)
  - Worker thread: capture → OCR → classify → queue findings
  - root.after() : drains queue and calls overlay.show() on each finding

Classification modes (set via --mode flag):
  regex   — fully offline; regex classifier only (default)
  hybrid  — regex first; escalate to LLM only when partial signals present
  llm     — every frame with text goes to the LLM (always online)

The worker thread only sends Finding objects to the main thread.
Raw OCR text never crosses the thread boundary and is never stored.
"""
import queue
import threading
import sys

from . import capture, ocr, classifier, event_log, reporter, config, llm_classifier
from .classifier import Finding
from .overlay import OverlayBanner

CAPTURE_INTERVAL = 2.0   # seconds between screen grabs
MIN_TEXT_LENGTH  = 15    # ignore frames with almost no text
QUEUE_POLL_MS    = 150   # how often the main thread checks the queue


def _detection_worker(
    finding_queue: queue.Queue,
    stop_event: threading.Event,
    debug: bool = False,
    mode: str = "regex",
    worker_url: str = "",
    device_token: str = "",
) -> None:
    """
    Runs in a daemon thread.  Captures screen, OCRs, classifies, and pushes
    Finding objects into finding_queue.  Raw OCR text is discarded after
    classification and never leaves this function.
    """
    cycle = 0
    while not stop_event.is_set():
        cycle += 1
        try:
            img = capture.grab_primary()
            text = ocr.extract_text(img)
            img.close()   # release memory immediately

            if debug:
                stripped = text.strip()
                char_count = len(stripped)
                preview = stripped[:300].replace("\n", "↵") if stripped else "(empty)"
                sys.stdout.write(
                    f"\n[debug #{cycle}] OCR {char_count} chars:  {preview}"
                    + (" …" if char_count > 300 else "")
                    + "\n"
                )
                sys.stdout.flush()

            if len(text.strip()) < MIN_TEXT_LENGTH:
                stop_event.wait(CAPTURE_INTERVAL)
                continue

            # ------------------------------------------------------------------
            # Tier 1: regex classifier (always runs, fully offline)
            # ------------------------------------------------------------------
            findings = classifier.classify(text)

            if findings:
                if debug:
                    for f in findings:
                        sys.stdout.write(
                            f"  [debug] regex: {f.tactic} @ {f.confidence:.2f}\n"
                        )
                    sys.stdout.flush()
                for f in findings:
                    finding_queue.put_nowait(f)

            elif mode in ("llm", "hybrid"):
                # --------------------------------------------------------------
                # Tier 2: LLM escalation
                # llm mode  — always escalate (every frame with text)
                # hybrid    — only when regex detected partial signals but no
                #             finding crossed threshold
                # --------------------------------------------------------------
                escalate = (
                    mode == "llm"
                    or classifier.should_escalate_to_llm(text)
                )

                if escalate:
                    if debug:
                        reason = "llm mode" if mode == "llm" else "partial regex signals"
                        sys.stdout.write(f"  [debug] escalating to LLM ({reason})…\n")
                        sys.stdout.flush()

                    llm_finding, reasoning = llm_classifier.classify_via_llm(
                        text, worker_url, device_token
                    )

                    if debug:
                        if llm_finding:
                            sys.stdout.write(
                                f"  [debug] LLM: {llm_finding.tactic}"
                                f" @ {llm_finding.confidence:.2f}"
                                f" | {reasoning}\n"
                            )
                        else:
                            sys.stdout.write(f"  [debug] LLM: NONE | {reasoning}\n")
                        sys.stdout.flush()

                    if llm_finding:
                        finding_queue.put_nowait(llm_finding)

                elif debug:
                    sys.stdout.write("  [debug] no notable regex signals — LLM skipped\n")
                    sys.stdout.flush()

        except Exception as exc:
            sys.stderr.write(f"[detector] loop error: {exc}\n")

        stop_event.wait(CAPTURE_INTERVAL)

    capture.close()


def run(debug: bool = False, mode: str = "regex") -> None:
    cfg = config.load()
    device_token = cfg["device_token"]
    worker_url   = cfg.get("worker_url", "")

    mode_note = (
        "fully offline"
        if mode == "regex"
        else ("cloud-required" if mode == "llm" else "regex first, LLM on uncertain frames")
    )

    print("Scam Coercion Detector starting.")
    print(f"Device token : {device_token}")
    print(f"Worker URL   : {worker_url or '(not configured)'}")
    print(f"Mode         : {mode.upper()} — {mode_note}")

    if worker_url:
        ok = reporter.register_device(worker_url, device_token)
        print(f"Cloud        : {'device registered' if ok else 'registration failed — offline fallback'}")

    if mode != "regex" and not worker_url:
        print("WARNING: mode is not 'regex' but no worker_url is set — LLM calls will silently fail.")

    print("Press Ctrl+C to stop.\n")

    finding_queue: queue.Queue[Finding] = queue.Queue()
    stop_event = threading.Event()

    worker = threading.Thread(
        target=_detection_worker,
        args=(finding_queue, stop_event, debug, mode, worker_url, device_token),
        daemon=True,
    )
    worker.start()

    overlay = OverlayBanner()

    def poll_queue() -> None:
        findings: list[Finding] = []
        while True:
            try:
                findings.append(finding_queue.get_nowait())
            except queue.Empty:
                break

        if findings:
            best = max(findings, key=lambda f: f.confidence)
            print(f"[alert] {best.tactic} @ {best.confidence:.2f} — {best.description}")

            event = event_log.log_event(tactic=best.tactic, confidence=best.confidence)
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
