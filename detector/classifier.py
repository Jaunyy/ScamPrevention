"""
Coercion-tactic classifier.

Uses weighted regex pattern groups — NOT a keyword blocklist.  Each tactic
requires enough pattern weight to exceed its threshold, which suppresses
false positives from isolated common words.

Returns a list of Finding(tactic, confidence, description) sorted by
confidence descending.  Only findings at or above threshold are returned.
Raw text is never stored; only the structured result leaves this module.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class Finding:
    tactic: str
    confidence: float   # 0.0–1.0
    description: str    # human-readable label for the overlay


# ---------------------------------------------------------------------------
# Taxonomy definition
# Each entry: (compiled_regex, weight)
# Confidence = min(1.0, accumulated_weight / threshold)
# Only fires if accumulated_weight >= threshold.
# ---------------------------------------------------------------------------

def _p(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


TACTICS: dict[str, dict] = {

    "URGENCY": {
        "description": "Urgency / time pressure",
        "patterns": [
            (_p(r"\b(quick|hurry|hurry up|fast)\b.{0,30}\b(before|now|gone)\b"), 0.35),
            (_p(r"\b(expires?|expiring|expir\w+)\b"), 0.30),
            (_p(r"\blimited.{0,10}(time|offer|deal)\b"), 0.35),
            (_p(r"\bnow or never\b"), 0.50),
            (_p(r"\blast chance\b"), 0.40),
            (_p(r"\bact now\b"), 0.40),
            (_p(r"\bonly \d+\s*(minutes?|seconds?|hours?|mins?|secs?)\s*(left|remaining)\b"), 0.55),
            (_p(r"\bdon.t (miss|wait|hesitate)\b.{0,20}\b(offer|deal|chance)\b"), 0.35),
            (_p(r"\btime.{0,8}(running out|is up|limit)\b"), 0.40),
            (_p(r"\b(today only|right now|immediately)\b"), 0.25),
        ],
        "threshold": 0.40,
    },

    "SECRECY": {
        "description": "Secrecy / hiding from parents",
        "patterns": [
            (_p(r"\bdon.t\s+tell\s+(your\s+)?(parents?|mom|dad|mommy|daddy|guardian|anyone)\b"), 0.75),
            (_p(r"\bkeep\s+(this\s+)?(between\s+us|secret|private|quiet)\b"), 0.60),
            (_p(r"\bour\s+(little\s+)?secret\b"), 0.60),
            (_p(r"\bdon.t\s+show\s+(anyone|your\s+parents?|them)\b"), 0.65),
            (_p(r"\bparents?.{0,20}(don.t|won.t|shouldn.t|can.t|needn.t)\s*(know|find\s*out|see|tell)\b"), 0.70),
            (_p(r"\b(delete|clear).{0,15}(this|chat|message|history)\s*(after|when|once)\b"), 0.55),
            (_p(r"\bjust\s+between\s+(you\s+and\s+me|us)\b"), 0.55),
            (_p(r"\bno\s+one\s+(else\s+)?needs?\s+to\s+know\b"), 0.65),
            (_p(r"\b(private|secret)\s+(deal|trade|offer)\b"), 0.45),
        ],
        "threshold": 0.55,
    },

    "FALSE_AUTHORITY": {
        "description": "False authority / platform impersonation",
        "patterns": [
            (_p(r"\b(i.?m|i\s+am|this\s+is)\s+(a\s+|an\s+)?(roblox|xbox|fortnite|epic(\s+games)?|minecraft|discord)\s+(admin|staff|mod(erator)?|developer|employee|official|support|team)\b"), 0.80),
            (_p(r"\b(official|verified)\s+(roblox|xbox|epic|fortnite|minecraft|discord)\b"), 0.70),
            (_p(r"\b(i\s+work\s+for|i.?m\s+from|i\s+represent)\s+(roblox|microsoft|xbox|epic|fortnite|activision|nintendo)\b"), 0.80),
            (_p(r"\b(roblox|xbox|epic|fortnite)\s+(admin|staff|moderator|developer|support)\s+(here|account|checking)\b"), 0.75),
            (_p(r"\bas\s+(a|an)\s+(moderator|admin|staff\s+member|official)\s+(i\s+can|i\s+have|i\s+will)\b"), 0.70),
            (_p(r"\b(selected|chosen|flagged)\s+(your\s+)?(account|profile)\s+for\s+(free|special|reward|prize)\b"), 0.65),
            (_p(r"\bgive\s+you\s+free\s+(robux|v.?bucks|coins|items?|skins?)\b.{0,30}\b(i.?m|because|as)\b"), 0.55),
            (_p(r"\bverif(y|ied|ication)\s+(your\s+)?(account|identity)\s+(to\s+receive|to\s+get|for\s+free)\b"), 0.65),
        ],
        "threshold": 0.65,
    },

    "RECIPROCITY": {
        "description": "Go-first / reciprocity trap",
        "patterns": [
            (_p(r"\bsend\s+(yours?|it|them|mine)\s+(first|1st)\b"), 0.55),
            (_p(r"\b(trust\s*trade|trust\s*trading)\b"), 0.75),
            # weight below threshold so it needs corroboration; excludes spatial "first at/in/on"
            (_p(r"\byou\s+go\s+first\b(?!\s+(at|in|on|to|around|through|over|across))"), 0.45),
            (_p(r"\bi.ll\s+send\s+(mine|it|after|back|second)\b.{0,30}\byou\s+(send|go)\b"), 0.65),
            (_p(r"\bsend\s+(me|it).{0,20}i.ll\s+(send|give|trade)\b"), 0.65),
            (_p(r"\bi\s+(promise|swear|guarantee)\s+(i.ll|to)\s+(send|give|trade)\b"), 0.50),
            (_p(r"\bjust\s+send\s+(me|it)\s+(and|then)\s+i.ll\b"), 0.70),
            (_p(r"\bi\s+(already\s+)?(sent|gave|traded)\s+(mine|it).{0,30}(your turn|now you|send yours)\b"), 0.70),
            (_p(r"\bfair\s+trade.{0,20}(you|send)\s+first\b"), 0.60),
            (_p(r"\b(quick|fast)\s+trade.{0,20}(trust|first|send)\b"), 0.50),
        ],
        "threshold": 0.55,
    },

    "CREDENTIAL_REQUEST": {
        "description": "Credential / account info request",
        "patterns": [
            (_p(r"\b(what.?s|tell me|give me|send me|share)\s+(your\s+)?(password|pass(word)?|pw)\b"), 0.80),
            (_p(r"\b(your\s+)?(username\s+and\s+password|login\s+(info|details|credentials))\b"), 0.80),
            (_p(r"\b(2fa|two.factor|two\s+factor|2\s*factor)\s+(code|token|pin)\b"), 0.75),
            (_p(r"\b(auth(entication)?|verification|confirm\w*)\s+(code|number|pin)\b"), 0.65),
            (_p(r"\b(can\s+i|let\s+me)\s+(borrow|use|have|access)\s+(your\s+)?(account|login|profile)\b"), 0.70),
            (_p(r"\blog\s*in\s+(to|with)\s+(my\s+link|this\s+link|here)\b"), 0.70),
            (_p(r"\b(email|e.mail)\s+and\s+(password|pass)\b"), 0.80),
            (_p(r"\bshare\s+(your\s+)?(account|login|credentials|access)\b"), 0.65),
            (_p(r"\b(sign\s+in|log\s+in).{0,20}(for\s+me|on\s+my|to\s+get)\b"), 0.60),
            (_p(r"\bsecurity\s+(question|answer|code)\b.{0,20}(tell|send|give)\b"), 0.60),
        ],
        "threshold": 0.65,
    },

    "PAYMENT_REQUEST": {
        "description": "Payment / gift card / QR request",
        "patterns": [
            (_p(r"\b(gift\s*card|giftcard)\s*(code|pin|number)?\b"), 0.65),
            (_p(r"\b(itunes|google\s+play|amazon|steam|apple)\s+(gift\s*card|card|code)\b"), 0.75),
            (_p(r"\b(robux|v.?bucks|minecoins|coins)\s+(code|card|voucher)\b"), 0.70),
            (_p(r"\bsend\s+(me\s+)?\$\s*\d+\b"), 0.75),
            (_p(r"\b(venmo|cashapp|cash\s+app|paypal|zelle|crypto|bitcoin|ethereum)\b"), 0.55),
            (_p(r"\bscan\s+(this\s+)?(qr|qr\s*code|barcode)\b"), 0.70),
            (_p(r"\b(send|buy|pay).{0,20}(for\s+me|me\s+robux|me\s+v.?bucks)\b"), 0.65),
            (_p(r"\b(card\s+number|cvv|credit\s+card|debit\s+card)\b"), 0.80),
            (_p(r"\b(wire|transfer|deposit).{0,15}(money|funds|cash)\b"), 0.70),
            (_p(r"\bpay.{0,10}(me|us)\s+and\s+(i.ll|you.ll|we.ll)\b"), 0.65),
        ],
        "threshold": 0.55,
    },
}


def classify(text: str) -> list[Finding]:
    """
    Classify text against all tactics.  Returns findings at or above threshold,
    sorted by confidence descending.  Never stores or returns the input text.
    """
    if not text or not text.strip():
        return []

    findings: list[Finding] = []

    for tactic_name, tactic in TACTICS.items():
        score = 0.0
        for pattern, weight in tactic["patterns"]:
            if pattern.search(text):
                score += weight

        if score >= tactic["threshold"]:
            confidence = min(1.0, score / tactic["threshold"])
            findings.append(Finding(
                tactic=tactic_name,
                confidence=round(confidence, 3),
                description=tactic["description"],
            ))

    findings.sort(key=lambda f: f.confidence, reverse=True)
    return findings
