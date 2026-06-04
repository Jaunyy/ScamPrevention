"""
Entry point: python3 run_detector.py [--debug]

--debug   Print the raw OCR text extracted each cycle so you can verify
          what Tesseract sees before the classifier runs.
"""
import argparse
from detector.main import run

parser = argparse.ArgumentParser(description="Scam Coercion Detector")
parser.add_argument(
    "--debug",
    action="store_true",
    help="Print raw OCR text each capture cycle",
)
args = parser.parse_args()

run(debug=args.debug)
