#!/usr/bin/env bash
set -e

echo "==> Checking Homebrew..."
if ! command -v brew &>/dev/null; then
  echo "Homebrew not found. Install from https://brew.sh then re-run this script."
  exit 1
fi

echo "==> Installing Tesseract OCR..."
brew install tesseract

echo "==> Installing Python dependencies..."
pip3 install -r requirements.txt

echo "==> Setup complete."
echo ""
echo "IMPORTANT: If you haven't already, grant Screen Recording permission to your"
echo "terminal app in System Settings → Privacy & Security → Screen Recording,"
echo "then quit and relaunch the terminal before running the detector."
echo ""
echo "Run verify_capture.py first to confirm screen recording works:"
echo "  python3 verify_capture.py"
