# Scam Coercion Detector

A child-safety tool that watches game chat in real time and alerts kids when it detects online scam or coercion tactics — with a parent dashboard to review flagged events.

## What it does

Kids playing online games (Roblox, Xbox, Epic/Fortnite) are frequently targeted by scammers using a predictable set of psychological tactics. This tool runs locally on the child's Mac, periodically captures the screen, OCRs the text, and classifies it against a **coercion-tactic taxonomy** to distinguish real threats from normal game chat.

When a tactic fires, a calm non-blocking orange banner appears at the top of the screen telling the child it looks like a scam and to talk to a parent. The flagged event (tactic type + confidence, no raw text) is sent to a Cloudflare Worker and stored in a D1 database so the parent can review a timeline on a hosted dashboard.

### Detected tactics

| Tactic | Example |
|---|---|
| **Urgency** | "Quick, only 3 minutes before this expires!" |
| **Secrecy** | "Don't tell your parents about this, keep it between us" |
| **False authority** | "I'm a Roblox admin and I've selected your account for free Robux" |
| **Reciprocity / go-first** | "Trust trade — you send first, then I'll send mine" |
| **Credential request** | "Tell me your username and password so I can fix your account" |
| **Payment / gift card** | "Send me a $50 iTunes gift card and I'll give you V-Bucks" |

## Architecture

```
Kid's Mac                       Cloudflare (free tier)
─────────────────────────       ──────────────────────────────────────
mss (screen capture, 2s)
  │
  ▼
pytesseract OCR
  │  (text discarded after classify)
  ▼
Tactic classifier
  │  (structured event only)
  ├──► Tkinter overlay banner ──► child sees warning
  ├──► ~/.scam_detector/events.jsonl (local log)
  └──► POST /events ──────────► Cloudflare Worker (Workers + D1)
                                        │
                          GET /events ◄─┘
                                 │
                          Cloudflare Pages dashboard ──► parent views timeline
```

## Setup

### Prerequisites

- macOS (windowed game mode; full-screen overlay is a v2 item)
- Homebrew: https://brew.sh
- Node.js (for Wrangler, if deploying the cloud side)

### 1. Install dependencies

```bash
bash setup.sh
```

This installs Tesseract via Homebrew and creates a Python venv with `mss`, `pytesseract`, `Pillow`, and `requests`.

### 2. Grant Screen Recording permission

**System Settings → Privacy & Security → Screen Recording → enable your Terminal (or VS Code)**

Then **quit and relaunch** that app. Without this, `mss` silently returns a black frame.

### 3. Verify capture works

```bash
source .venv/bin/activate
python3 verify_capture.py
```

### 4. Run the detector

```bash
python3 run_detector.py
# Add --debug to print raw OCR text each cycle
python3 run_detector.py --debug
```

On first run it prints your **device token** — share this with the parent dashboard to connect them.

### 5. Test the classifier offline (no screen / Tesseract needed)

```bash
python3 test_classifier.py
```

## Cloudflare deployment (parent dashboard)

### Deploy the Worker + D1

```bash
npm install -g wrangler
wrangler login

cd cloudflare/worker
wrangler d1 create scam-detector-db
# Copy the database_id printed and paste it into wrangler.toml
wrangler d1 execute scam-detector-db --remote --file=schema.sql
wrangler deploy
```

### Deploy the dashboard

```bash
cd cloudflare/dashboard
wrangler pages deploy . --project-name scam-detector-dashboard
```

### Connect the detector to the cloud

Edit `~/.scam_detector/config.json` and set `worker_url` to your deployed Worker URL:

```json
{
  "device_token": "YOUR12CHARTOKEN",
  "worker_url": "https://scam-detector-worker.YOUR_SUBDOMAIN.workers.dev"
}
```

### Open the dashboard

```
https://YOUR_PAGES_URL.pages.dev?worker=https://scam-detector-worker.YOUR_SUBDOMAIN.workers.dev
```

Enter your device token once — the dashboard auto-refreshes every 30 seconds.

## Privacy by design

- **Raw screen content is never stored or transmitted.** The OCR text is analyzed in memory and discarded immediately after the classifier runs.
- Only structured events are persisted: `{tactic, confidence, timestamp}` — no screenshots, no message text, no usernames.
- The local event log (`~/.scam_detector/events.jsonl`) and config (`~/.scam_detector/config.json`) are outside this repository and covered by `.gitignore`.
- The detector runs fully offline if no Worker URL is configured — the overlay and local log work without any network connection.

## Known limitations (v2)

- The Tkinter overlay captures pointer events over its own area. True click-through requires upgrading to a PyObjC `NSWindow` at `NSFloatingWindowLevel` with `setIgnoresMouseEvents_(True)`.
- Full-screen exclusive game mode is not handled. Run games in windowed mode for the demo.
