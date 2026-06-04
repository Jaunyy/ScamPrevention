"""
OCR debug tool.

Captures the screen once, runs the full preprocessing pipeline, saves both
the raw and the preprocessed image to /tmp so you can open them and see
exactly what Tesseract sees.  Then runs Tesseract in PSM 3 and PSM 6 and
prints both results side-by-side so you can compare extraction quality.

Usage:
    source .venv/bin/activate
    python3 ocr_debug.py [--region top|bottom|left|right|full]

--region  Crop to a screen quadrant before OCR.  Useful when chat lives in
          one corner and you want to reduce noise from the rest of the UI.
          Defaults to 'full' (whole primary monitor).
"""
import argparse
import sys
from pathlib import Path

try:
    from PIL import Image, ImageStat
    import pytesseract
    from detector.capture import grab_primary
    from detector.ocr import _preprocess, _TESS_PSM3, _TESS_PSM6, _TARGET_WIDTH, _MAX_SCALE, _BINARIZE_THRESHOLD
except ImportError as e:
    print(f"Import error: {e}")
    print("Run from the project root with the venv active:")
    print("  source .venv/bin/activate && python3 ocr_debug.py")
    sys.exit(1)

RAW_PATH       = Path("/tmp/scam_detector_raw.png")
PROCESSED_PATH = Path("/tmp/scam_detector_processed.png")

REGIONS = {
    "full":   None,
    "top":    lambda w, h: (0, 0, w, h // 2),
    "bottom": lambda w, h: (0, h // 2, w, h),
    "left":   lambda w, h: (0, 0, w // 2, h),
    "right":  lambda w, h: (w // 2, 0, w, h),
}


def _divider(label: str, width: int = 72) -> str:
    return f"── {label} " + "─" * max(0, width - len(label) - 4)


def main() -> None:
    parser = argparse.ArgumentParser(description="OCR debug — see what Tesseract sees")
    parser.add_argument(
        "--region",
        choices=list(REGIONS),
        default="full",
        help="Screen region to OCR (default: full)",
    )
    args = parser.parse_args()

    # ── Capture ──────────────────────────────────────────────────────────────
    print("Capturing screen…")
    raw = grab_primary()

    crop_fn = REGIONS[args.region]
    if crop_fn is not None:
        box = crop_fn(raw.width, raw.height)
        raw = raw.crop(box)
        print(f"Cropped to {args.region} half: {raw.width}x{raw.height}")

    raw.save(RAW_PATH)
    print(f"Raw image            → {RAW_PATH}  ({raw.width}x{raw.height} px)")

    # ── Preprocess ───────────────────────────────────────────────────────────
    processed = _preprocess(raw)
    raw.close()
    processed.save(PROCESSED_PATH)

    stat       = ImageStat.Stat(processed)
    mean_b     = stat.mean[0]
    scale_used = processed.width / (raw.width if args.region == "full" else processed.width)

    print(f"Preprocessed image   → {PROCESSED_PATH}  ({processed.width}x{processed.height} px)")
    print()
    print("── Preprocessing settings ──")
    print(f"  _TARGET_WIDTH       = {_TARGET_WIDTH}  (upscale if image is narrower)")
    print(f"  _MAX_SCALE          = {_MAX_SCALE}×")
    print(f"  _BINARIZE_THRESHOLD = {_BINARIZE_THRESHOLD}  (pixels above → white)")
    print(f"  Mean brightness after autocontrast: {mean_b:.1f} / 255")
    print(f"  Inversion applied: {'yes (light-on-dark detected)' if mean_b < 128 else 'no (dark-on-light)'}")
    print()

    # ── PSM comparison ───────────────────────────────────────────────────────
    results = {}
    for psm, label in [(3, "PSM 3 — auto page segmentation (default)"),
                       (6, "PSM 6 — single uniform block")]:
        config = f"--psm {psm} --oem 3"
        text = pytesseract.image_to_string(processed, config=config)
        results[psm] = text.strip()

    winner = max(results, key=lambda p: len(results[p]))

    for psm, label in [(3, "PSM 3 — auto page segmentation (default)"),
                       (6, "PSM 6 — single uniform block")]:
        text    = results[psm]
        n_chars = len(text)
        n_words = len(text.split())
        flag    = " ◀ more text" if psm == winner and len(results[3]) != len(results[6]) else ""
        print(_divider(f"{label}  ({n_chars} chars, {n_words} words){flag}"))
        if text:
            # Print each line, prefixed with "│ " for readability
            for line in text.splitlines():
                if line.strip():
                    print(f"  {line}")
        else:
            print("  (no text extracted)")
        print()

    # ── Quick classifier check ───────────────────────────────────────────────
    print(_divider("Classifier check (regex) on PSM 3 output"))
    try:
        from detector.classifier import classify
        combined = results[3] or results[6]
        findings = classify(combined)
        if findings:
            for f in findings:
                print(f"  ALERT  {f.tactic} @ {f.confidence:.2f} — {f.description}")
        else:
            print("  No tactic detected.")
    except Exception as exc:
        print(f"  (classifier unavailable: {exc})")

    print()
    print("Open images to inspect visually:")
    print(f"  open {RAW_PATH}")
    print(f"  open {PROCESSED_PATH}")


if __name__ == "__main__":
    main()
