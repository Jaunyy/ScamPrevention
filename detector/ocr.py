"""
OCR layer: converts a PIL image to plain text using Tesseract.
Text is returned in memory and never persisted.

Preprocessing pipeline (applied in order):
  1. Grayscale
  2. Upscale if narrower than _TARGET_WIDTH — Tesseract needs characters
     at least ~20 px tall for reliable recognition; capped at _MAX_SCALE
     to avoid blurring very small sources beyond usefulness
  3. Autocontrast — stretches histogram to fill 0-255
  4. Binarize — detects light-on-dark screens (game UIs typically are) and
     inverts before thresholding, so anti-aliased fonts become crisp
     black-on-white regardless of the game's colour scheme
  5. Sharpen

PSM notes:
  PSM 3 (default) — fully automatic page segmentation.  Best for full game
    screens with mixed layout: chat overlay, HUD, player names, UI widgets.
  PSM 6            — single uniform text block.  Better when the caller has
    already cropped to an isolated chat-box region.
"""
from PIL import Image, ImageFilter, ImageOps, ImageStat
import pytesseract

_TESS_PSM3 = "--psm 3 --oem 3"
_TESS_PSM6 = "--psm 6 --oem 3"

# Default changed from PSM 6 → PSM 3: full-screen game captures contain
# multiple text regions; auto page-seg finds them all.
_TESS_CONFIG = _TESS_PSM3

_TARGET_WIDTH       = 1200  # upscale if image is narrower than this
_MAX_SCALE          = 2.0   # never upscale more than 2× (avoids LANCZOS blur)
_BINARIZE_THRESHOLD = 128   # pixels above this → white; at or below → black
                             # lower value: keeps more gray pixels as text
                             # higher value: more aggressive noise removal


def _preprocess(img: Image.Image) -> Image.Image:
    img = img.convert("L")

    # Step 1: upscale small images
    w, h = img.size
    if w < _TARGET_WIDTH:
        scale = min(_MAX_SCALE, _TARGET_WIDTH / w)
        img = img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)

    # Step 2: stretch histogram
    img = ImageOps.autocontrast(img, cutoff=2)

    # Step 3: binarize
    # Game UIs usually have light text on dark backgrounds; detect and invert
    # so Tesseract always sees dark text on a light background.
    if ImageStat.Stat(img).mean[0] < 128:
        img = ImageOps.invert(img)
    img = img.point(lambda p: 255 if p > _BINARIZE_THRESHOLD else 0)

    # Step 4: sharpen
    img = img.filter(ImageFilter.SHARPEN)
    return img


def extract_text(img: Image.Image, psm: int | None = None) -> str:
    """
    Run Tesseract on img and return the extracted string.

    psm: override page segmentation mode (default: 3).
         3 = auto, better for full game screens
         6 = single block, better for a pre-cropped chat region
    Returns empty string if Tesseract is unavailable or OCR fails.
    """
    config = f"--psm {psm} --oem 3" if psm is not None else _TESS_CONFIG
    try:
        processed = _preprocess(img)
        return pytesseract.image_to_string(processed, config=config)
    except Exception:
        return ""
