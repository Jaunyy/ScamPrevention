# Scam Coercion Detector

A desktop child safety tool that watches a child's game screen in real time, OCRs on-screen text, and alerts the child when it detects scam or coercion tactics with a parent dashboard to review flagged events.

---

## Problem & Motivation

Online games are no longer just games. Roblox, Fortnite, Minecraft, and Xbox Live are social platforms where children spend hours a day talking to strangers. Approximately 45% of Roblox's user base is 12 or younger, and a significant portion of that population has limited experience recognizing manipulation.

The attacks are almost never technical. Scammers do not exploit zero days or compromise accounts through malware. They exploit psychology:

- **Urgency** — "Only 3 minutes left before this offer disappears" forces a decision before the child can think or ask a parent.
- **Secrecy** — "Don't tell your parents about this" isolates the child from the people most likely to intervene.
- **False authority** — "I'm a Roblox admin and I've selected your account for free Robux" exploits a child's deference to perceived official figures.
- **Reciprocity traps** — "Trust trade — you send first and I'll send mine" exploit a child's good faith in social exchanges.
- **Credential and payment requests** — asking for passwords, 2FA codes, or gift card codes directly. The FBI has documented that offenders in sextortion schemes targeting minors demand money and/or gift cards from their victims [[3]](#references).
- **Off-platform moves** — "Let's trade on Discord" redirects a child from a moderated game environment to an unmoderated channel, removing the platform's safety net. The FBI has explicitly named asking a victim to "move to a different app" as a documented warning sign for these schemes [[2]](#references).

The scale of documented harm is significant. In a single year, the FBI and its partners received over 7,000 reports of online financial sextortion targeting minors, identifying at least 3,000 victims, predominantly boys, and linking the schemes to more than a dozen suicides [[1]](#references). In 2025, the FBI's Internet Crime Complaint Center issued a separate alert specifically about "The Com," a network of criminal actors who coordinate attacks on minors across gaming platforms including Roblox and Discord, using precisely these social-engineering playbooks [[4]](#references).

These are not isolated incidents or edge cases. They are a documented, organized threat directed at the age group that uses gaming platforms most heavily.

The core insight behind this project: **coercion has a detectable psychological structure.** A scammer trying to extract a gift card code from a 10-year-old in Roblox will use recognizable patterns, not a random vocabulary. A classifier that understands the *intent structure* of these tactics (rather than a keyword blocklist, which any scammer trivially circumvents) can detect them reliably.

---

## Architecture

```
Kid's Mac (runs offline by default)       Cloudflare (free tier)
─────────────────────────────────────     ─────────────────────────────────────
mss screen capture  (every 2 seconds)
         │
         ▼
pytesseract / Tesseract OCR
  │  text analyzed in memory, then discarded
  ▼
Classifier  ──── Tier 1: weighted regex (fully offline)
                 Tier 2: compound AND + intent suppression (offline)
                 Tier 3: Workers AI / Llama 3.1 8B (hybrid/llm modes only)
  │
  ├──► Tkinter overlay banner  ──► child sees calm warning
  ├──► ~/.scam_detector/events.jsonl  (local structured log)
  └──► POST /events ─────────────►  Cloudflare Worker  ──► D1 database
                                                │
                                    GET /events ◄┘
                                         │
                                 Cloudflare Pages  ──► parent dashboard
```

**Local detector** (`detector/`) — Python, runs on the child's Mac. Captures the primary monitor every 2 seconds using `mss`, runs Tesseract OCR on a preprocessed grayscale image, and feeds extracted text to the classifier. The overlay is a Tkinter banner that appears at the top of the screen and auto dismisses after 30 seconds. The detector is designed to run fully offline; the cloud connection is optional.

**Three classification modes** (selected with `--mode`):

| Mode | Behavior | Network required |
|---|---|---|
| `regex` (default) | Weighted regex classifier only | No |
| `hybrid` | Regex first; escalates to LLM only when partial signals are present but no finding crossed threshold | Only on uncertain frames |
| `llm` | Every frame with text goes to the LLM | Yes |

**Cloudflare Worker + D1** — a Workers script receives structured flagged events (`POST /events`) authenticated by a device token, validates the tactic against the allow-list, and stores them in a D1 (SQLite) database. A separate `POST /classify` route proxies to Workers AI without storing the text.

**Cloudflare Pages dashboard** — a single-page HTML/JS app that reads events from the Worker (`GET /events`) using the device token, displays a timeline of flagged events with tactic badges and confidence bars, and auto-refreshes every 30 seconds.

---

## Classifier Design

### Tactic Taxonomy

The classifier defines eight tactics:

| Tactic | What it detects |
|---|---|
| `URGENCY` | Time pressure to act before thinking |
| `SECRECY` | Instructions to hide the interaction from parents |
| `FALSE_AUTHORITY` | Impersonation of platform staff or admins |
| `RECIPROCITY` | Go-first / trust-trade traps |
| `CREDENTIAL_REQUEST` | Requests for passwords, login info, or 2FA codes |
| `PAYMENT_REQUEST` | Gift card codes, QR codes, money transfers |
| `FREE_ITEM_LURE` | Free in-game item offer paired with an engagement hook |
| `OFF_PLATFORM` | Attempts to move the conversation to an unmoderated channel |

### Tier 1 — Weighted Regex (offline)

Each tactic has a group of weighted regex patterns. Confidence is computed as the ratio of accumulated match weight to a per-tactic threshold. **No single pattern fires a tactic on its own** the classifier requires enough overlapping evidence to cross the threshold. This suppresses false positives from isolated common words.

Example: `URGENCY` requires accumulated weight ≥ 0.40. "Quick, only 3 minutes left" hits two patterns (0.35 + 0.55 = 0.90), comfortably above threshold. "right now" alone is weight 0.25. This is below threshold, no alert.

### Tier 2 — Compound Tactics with Intent Suppression (offline)

`FREE_ITEM_LURE` and `OFF_PLATFORM` use a compound AND mode: every named group must have at least one match before the tactic fires.

`FREE_ITEM_LURE` requires *both* a **lure group** ("free robux", "giving away skins") *and* a **hook group** ("DM me", "add me on discord") to match simultaneously. A child asking "does anyone know where I can get free skins?" matches the lure group but not the hook, and is also caught by suppression patterns that detect interrogative phrasing (`does anyone`, `where can i get`, etc.) — so it never fires.

This intent awareness, which is distinguishing the offerer from the asker, is the key design goal. A keyword blocklist on "free robux" would flag victims as well as attackers.

### Tier 3 — LLM Escalation (hybrid/llm modes)

In `hybrid` mode, the detector escalates to the LLM only when: (a) no regex finding crossed threshold, but (b) at least one notable pattern (weight ≥ 0.40) matched somewhere. Frames with no relevant keywords at all skip the LLM entirely. This keeps the large majority of frames processed entirely offline.

The LLM route (`POST /classify`) calls `@cf/meta/llama-3.1-8b-instruct` via Cloudflare Workers AI. The system prompt explicitly instructs the model on the offerer-vs-asker distinction and requires a JSON-only response:

```json
{"tactic": "FREE_ITEM_LURE", "confidence": 0.8, "reasoning": "one short sentence"}
```

The response is parsed defensively: markdown fences are stripped, the first `{…}` object is extracted with a regex, and any parse failure or unknown tactic name falls back to `{"tactic": "NONE", "confidence": 0}` rather than erroring.

---

## Privacy by Design

- **Raw screen content is never stored or transmitted.** The OCR text string is analyzed in memory and discarded after the classifier runs. It does not cross the worker thread boundary, is not written to any file, and is not sent to any external service.
- **Only structured events are persisted:** `{tactic, confidence, timestamp}` — no screenshots, no message text, no usernames.
- The local event log (`~/.scam_detector/events.jsonl`) and device config (`~/.scam_detector/config.json`) live outside the repository and are covered by `.gitignore`.
- The `POST /classify` Worker route passes the text to Workers AI and returns only the structured result. The text is not stored in D1 or logged anywhere.
- The detector runs fully offline in `--mode regex`. Cloud connection is opt-in; if `worker_url` is not configured, events are only written to the local log.

---

## Setup & Reproduction

### Prerequisites

- macOS (tested on macOS 15 with Python 3.14 via Homebrew)
- [Homebrew](https://brew.sh)
- Node.js (for Wrangler, if deploying the Cloudflare side)
- A free [Cloudflare account](https://cloudflare.com) (Workers + D1 + Pages — no paid plan required)

### Step 1 — Grant Screen Recording permission

**Before running anything else**, go to:

> System Settings → Privacy & Security → Screen Recording → enable your Terminal (or VS Code)

Then **quit and relaunch** that app. Without this, `mss` silently returns a black frame — Tesseract will extract nothing and no error is shown.

### Step 2 — Install Tesseract and the Tkinter extension

```bash
brew install tesseract
brew install python-tk@3.14   # required for the overlay; version must match your python
```

### Step 3 — Create a Python virtual environment and install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

> **Note:** `setup.sh` automates the Tesseract install and `pip install` step, but on macOS with Homebrew Python 3.14 the `pip3` call in that script hits PEP 668's externally-managed-environment restriction. The venv approach above is reliable.

### Step 4 — Verify screen capture

```bash
python3 verify_capture.py
```

This grabs one frame, checks it is non-black, reports pixel statistics, and saves a preview to `/tmp/scam_detector_verify.png`.

### Step 5 — Run the classifier test suite (no screen / Tesseract needed)

```bash
python3 test_classifier.py
```

Expected output:

```
[PASS] urgency                              →  URGENCY @ 1.00
[PASS] secrecy                              →  SECRECY @ 1.00
[PASS] false authority                      →  FALSE_AUTHORITY @ 1.00
[PASS] reciprocity                          →  RECIPROCITY @ 1.00
[PASS] credentials                          →  CREDENTIAL_REQUEST @ 1.00
[PASS] payment                              →  PAYMENT_REQUEST @ 1.00
[PASS] benign — normal game chat            →  no finding
[PASS] benign — you go first in a race      →  no finding
[PASS] free item lure with DM hook — FIRES  →  FREE_ITEM_LURE @ 0.82
[PASS] benign — asker seeking free skins (interrogative, no hook)  →  no finding
[PASS] benign — free item mention alone, no hook  →  no finding
[PASS] off-platform redirect alone — FIRES  →  OFF_PLATFORM @ 1.00

12/12 passed
```

### Step 6 — Run the detector

```bash
# Fully offline, regex classifier only (safe default)
python3 run_detector.py

# Hybrid: regex first, LLM only on ambiguous frames
python3 run_detector.py --mode hybrid

# Debug: prints OCR text and classifier decisions each cycle
python3 run_detector.py --mode hybrid --debug
```

On first run, the detector prints a 12-character **device token** (`~/.scam_detector/config.json`). This token authenticates all cloud communication and is needed to connect the parent dashboard.

#### OCR tuning

```bash
# Capture the screen, save preprocessed image to /tmp, print PSM 3 vs PSM 6 comparison
python3 ocr_debug.py

# Focus on the screen region where game chat typically appears
python3 ocr_debug.py --region bottom
```

### Step 7 — Deploy the Cloudflare backend (optional — detector works offline without this)

```bash
npm install -g wrangler
wrangler login

# Create D1 database, copy the printed database_id
cd cloudflare/worker
wrangler d1 create scam-detector-db

# Paste the database_id into wrangler.toml (replace REPLACE_WITH_YOUR_D1_DATABASE_ID)
wrangler d1 execute scam-detector-db --remote --file=schema.sql
wrangler deploy

# Deploy the parent dashboard
cd ../dashboard
wrangler pages deploy . --project-name scam-detector-dashboard
```

Set the Worker URL in the detector config:

```json
// ~/.scam_detector/config.json
{
  "device_token": "YOUR12CHARTOKEN",
  "worker_url": "https://scam-detector-worker.YOUR_SUBDOMAIN.workers.dev"
}
```

Open the dashboard:

```
https://YOUR_PAGES_SUBDOMAIN.pages.dev?worker=https://scam-detector-worker.YOUR_SUBDOMAIN.workers.dev
```

Enter your device token once — the dashboard auto-refreshes every 30 seconds and shows a color-coded timeline of flagged events.

---

## Evaluation & Limitations

### Test suite

The 12-case test suite in `test_classifier.py` covers all eight tactics (one positive case each), two confirmed false-positive regression cases (benign game chat, a child asking a question about free items), and two compound cases for the newer tactics. All 12 pass.

The suite runs entirely offline with no screen capture or Tesseract required, so it can be executed in any environment to verify classifier correctness after changes.

### Precision / recall tradeoff

The thresholds are tuned to **minimize false positives at the cost of some recall.** A child who encounters "free skins!!" in chat with no hook will not see an alert — the benign case correctly produces no finding. A child who sees "free skins!!" followed by "DM me first" will. The reasoning: a false positive (unnecessary alert on innocent text) erodes trust in the tool and teaches children to dismiss it. A false negative (missed alert) is unfortunate but is not the only safety net — parental supervision and in-game reporting still exist.

Bare lures without hooks are handled by hybrid mode: the LLM sees the full context and can use reasoning the regex cannot, but only for those ambiguous frames.

### OCR reliability

Tesseract performs reliably on high-contrast desktop text and IDE/editor windows, but game fonts vary significantly:

- Stylized or pixel-art fonts (common in Roblox) can produce garbled output.
- Text rendered on busy or animated backgrounds (game world imagery, particle effects) is harder to extract than text on a flat UI panel.
- Very small chat bubbles at standard game resolutions may fall below Tesseract's reliable minimum character height (~20 px).

The preprocessing pipeline (upscale to ≥ 1200 px, autocontrast, binarize, sharpen) and PSM 3 (automatic page segmentation) improve results on mixed-layout screens significantly versus the original PSM 6 + sharpen-only pipeline. The `ocr_debug.py` tool is provided to tune preprocessing for a specific game's visual style.

### LLM latency

`@cf/meta/llama-3.1-8b-instruct` on Workers AI takes 5–15 seconds on a warm worker and longer on a cold start. This is tolerable for the hybrid gate (the large majority of frames never call it) but makes `--mode llm` impractical for real-time use — it would fall behind the 2-second capture interval. Hybrid mode's primary value is handling edge cases that regex cannot, not replacing it.

### AI text classification reliability

AI-based text classification is inherently probabilistic. The LLM can be misled by obfuscation ("fr3e r0bux"), non-standard spelling, or short fragments that lack context. It can also false-positive on legitimate text that superficially resembles a tactic. The three-tier design (regex confidence → compound comparison → LLM escalation only for uncertain frames) is intended to constrain these failure modes by ensuring the LLM only sees frames that already have some signal.

### Known v2 items

- **Click-through overlay:** The Tkinter banner captures pointer events over its area. A PyObjC `NSWindow` at `NSFloatingWindowLevel` with `setIgnoresMouseEvents_(True)` would give true click-through, letting the child interact with the game while the warning is visible.
- **Full-screen game capture:** Games running in exclusive full-screen mode cannot be overlaid by a standard window. Addressing this requires either a system-level overlay (requires additional macOS permissions) or asking the child to play in windowed mode.
- **Multi-user / multi-device auth:** The v1 pairing model is a single shared token per device. A proper parent account with multiple linked child devices would require full authentication (email/password or OAuth), intentionally deferred for scope.
- **Windows support:** `mss` and `pytesseract` both support Windows; the overlay would need to swap Tkinter for a Win32 `WS_EX_LAYERED` window or equivalent.

---

## AI Usage Disclosure

This project was built using **Claude Code** (Anthropic's AI coding assistant) for scaffolding, implementation, and debugging across the full stack — Python detector, Cloudflare Worker, D1 schema, and Pages dashboard. Architecture decisions, the tactic taxonomy design, the privacy constraints, the precision/recall tradeoff, and the hybrid-gate logic were directed by me. Claude Code generated code to specification and was used iteratively: write → test → revise → test again. The 12-case test suite was designed by me and used to validate that classifier behavior matched intent after each change.

Specific areas where Claude Code was the primary implementer under my direction:

- The regex pattern groups and threshold values in `detector/classifier.py`
- The compound AND + suppression logic for `FREE_ITEM_LURE` and `OFF_PLATFORM`
- The Cloudflare Worker routes, D1 schema, and defensive JSON parsing for the LLM response
- The OCR preprocessing pipeline (upscaling, binarization, PSM selection)
- The hybrid escalation gate and the `should_escalate_to_llm` heuristic

All code in this repository was reviewed and understood before submission. This disclosure is provided in accordance with course requirements.

---

## References

1. FBI, NCMEC, and partner agencies. "FBI and Partners Issue National Public Safety Alert on Financial Sextortion Schemes." FBI.gov, 2022. <https://www.fbi.gov/news/press-releases/fbi-and-partners-issue-national-public-safety-alert-on-financial-sextortion-schemes>

2. FBI Los Angeles Field Office. "FBI Issues Warning About the Increase of Financial Sextortion Schemes Targeting Minors." FBI.gov. <https://www.fbi.gov/contact-us/field-offices/losangeles/news/fbi-issues-warning-about-the-increase-of-financial-sextortion-schemes-targeting-minors>

3. FBI Kansas City Field Office. "On Safer Internet Day, FBI Warns About the Dangers of Sextortion Schemes Against Minors." FBI.gov. <https://www.fbi.gov/contact-us/field-offices/kansascity/news/on-safer-internet-day-fbi-warns-about-the-dangers-of-sextortion-schemes-against-minors>

4. FBI Internet Crime Complaint Center (IC3). "IC3 Alert: Criminal Network 'The Com' Targeting Minors Across Online Platforms." IC3.gov, 2025. <https://www.ic3.gov/PSA/2025/PSA250723-3>
