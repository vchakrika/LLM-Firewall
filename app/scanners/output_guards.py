"""Output guard: runs on the model's reply BEFORE it reaches the user.

Three possible outcomes (action):
  clean    - nothing found, text unchanged
  redacted - secrets/cards removed, text modified, still delivered
  blocked  - canary leaked, reply withheld entirely
"""
import re

from app.config import CANARY_TOKEN

SECRETS_PATTERNS = {
    "OpenAI Key": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
    "Generic API Key": re.compile(r"(?i)api[_-]?key[\s:=]+['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"),
    "AWS Key": re.compile(r"AKIA[0-9A-Z]{16}"),
}
CREDIT_CARD = re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b")


def scan_output(output_text: str) -> dict:
    # 1. Canary check: the strongest signal that the system prompt leaked.
    if CANARY_TOKEN in output_text:
        return {
            "is_safe": False,
            "action": "blocked",
            "reason": "Critical: System prompt canary token leaked",
            "text": "Response blocked due to security boundary policy.",
        }

    text = output_text

    # 2. Redact leaked secrets
    for name, rx in SECRETS_PATTERNS.items():
        text = rx.sub(f"[REDACTED_{name.upper().replace(' ', '_')}]", text)

    # 3. Redact credit-card-shaped numbers
    text = CREDIT_CARD.sub("[REDACTED_CREDIT_CARD]", text)

    action = "clean" if text == output_text else "redacted"
    reason = "Clean" if action == "clean" else "Sensitive data redacted"
    return {"is_safe": True, "action": action, "reason": reason, "text": text}
