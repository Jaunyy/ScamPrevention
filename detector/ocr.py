"""
OCR layer: converts a PIL image to plain text using Tesseract.
Text is returned in memory and never persisted.
"""
from PIL import Image, ImageFilter, ImageOps
import pytesseract


# Tesseract config: single-block mode is faster for chat overlays
_TESS_CONFIG = "--psm 6 --oem 3"


def _preprocess(img: Image.Image) -> Image.Image:
    """Sharpen and increase contrast to improve OCR on game chat fonts."""
    img = img.convert("L")                     # grayscale
    img = ImageOps.autocontrast(img, cutoff=2) # stretch histogram
    img = img.filter(ImageFilter.SHARPEN)
    return img


def extract_text(img: Image.Image) -> str:
    """
    Run Tesseract on img and return the extracted string.
    Returns an empty string if Tesseract is not installed or OCR fails.
    """
    try:
        processed = _preprocess(img)
        text = pytesseract.image_to_string(processed, config=_TESS_CONFIG)
        return text
    except Exception:
        return ""
