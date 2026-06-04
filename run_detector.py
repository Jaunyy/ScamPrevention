"""
Entry point: python3 run_detector.py [--debug] [--mode {regex,hybrid,llm}]

--mode regex    Fully offline; regex classifier only (default)
--mode hybrid   Regex first; escalate to LLM only when partial signals present
--mode llm      Every frame with text goes to the LLM (always requires network)

--debug         Print raw OCR text and classifier decisions each cycle
"""
import argparse
from detector.main import run

parser = argparse.ArgumentParser(description="Scam Coercion Detector")
parser.add_argument(
    "--debug",
    action="store_true",
    help="Print OCR text and classifier decisions each capture cycle",
)
parser.add_argument(
    "--mode",
    choices=["regex", "hybrid", "llm"],
    default="regex",
    help="Classification mode (default: regex)",
)
args = parser.parse_args()

run(debug=args.debug, mode=args.mode)
