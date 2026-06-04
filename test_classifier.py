"""
Smoke-test the classifier without needing screen recording or Tesseract.
Run with:  python3 test_classifier.py
"""
from detector.classifier import classify

CASES = [
    # (label, text, expected_tactic_or_None)
    (
        "urgency",
        "Quick, only 3 minutes left before this offer expires!",
        "URGENCY",
    ),
    (
        "secrecy",
        "Hey don't tell your parents about this ok? Keep it between us",
        "SECRECY",
    ),
    (
        "false authority",
        "I'm a Roblox admin and I've selected your account for free Robux",
        "FALSE_AUTHORITY",
    ),
    (
        "reciprocity",
        "Trust trade! You go first, then I'll send mine after, I promise",
        "RECIPROCITY",
    ),
    (
        "credentials",
        "Can you tell me your username and password so I can fix your account?",
        "CREDENTIAL_REQUEST",
    ),
    (
        "payment",
        "Send me a $50 iTunes gift card code and I'll give you V-Bucks",
        "PAYMENT_REQUEST",
    ),
    (
        "benign — normal game chat",
        "Quick, I'm almost dead! Hurry and help me",
        None,
    ),
    (
        "benign — you go first in a race",
        "You go first at the starting line, I'll follow",
        None,
    ),
    # --- FREE_ITEM_LURE + OFF_PLATFORM ---
    (
        "free item lure with DM hook — FIRES",
        "I'll give you free robux, DM me first",
        "FREE_ITEM_LURE",
    ),
    (
        "benign — asker seeking free skins (interrogative, no hook)",
        "does anyone know where I can get free skins?",
        None,
    ),
    (
        "benign — free item mention alone, no hook",
        "free skins!!",
        None,
    ),
    (
        "off-platform redirect alone — FIRES",
        "let's move to Discord to trade",
        "OFF_PLATFORM",
    ),
]


def main() -> None:
    passed = 0
    failed = 0
    for label, text, expected in CASES:
        findings = classify(text)
        tactics = [f.tactic for f in findings]

        if expected is None:
            ok = len(findings) == 0
        else:
            ok = expected in tactics

        status = "PASS" if ok else "FAIL"
        if ok:
            passed += 1
        else:
            failed += 1

        detail = (
            f"{findings[0].tactic} @ {findings[0].confidence:.2f}"
            if findings else "no finding"
        )
        print(f"[{status}] {label:35s}  →  {detail}")

    print(f"\n{passed}/{passed+failed} passed")


if __name__ == "__main__":
    main()
