"""Input guard v0: regex blocklist + one structural check.

This is deliberately UNCHANGED in behaviour from your original so the v0 benchmark
is a true baseline. Stages 1-3 will improve it and we'll measure each step.
"""
import re

# Each rule is a regex searched case-insensitively against the prompt.
SUSPICIOUS_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"disregard prior constraints",
    r"system override",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"you are now (an unfiltered|DAN)",
    r"--- END OF SYSTEM CONTEXT ---",
    r"output (the )?exact text of (the )?initial system prompt",
    r"admin_command",
    r"cancel all previous prompts",
    r"supers?e?de all previous",  # matches the misspelling "supercede" and "supersede"
]

# Compile once at import time instead of on every request.
_COMPILED = [(p, re.compile(p, re.IGNORECASE)) for p in SUSPICIOUS_PATTERNS]


def scan_input(prompt: str) -> dict:
    """Return a verdict dict: is_valid, reason, score (0.0 safe .. 1.0 certain attack)."""
    # 1. Heuristic rules
    for pattern, rx in _COMPILED:
        if rx.search(prompt):
            return {"is_valid": False, "reason": f"Heuristic match: {pattern}", "score": 1.0}

    # 2. Structural check.
    # KNOWN WEAKNESS (fixed in Stage 2): '---' is also Markdown, so this will
    # eventually block legitimate users. Kept as-is for a faithful baseline.
    if prompt.count("---") >= 2 or "[ADMIN" in prompt.upper():
        return {"is_valid": False, "reason": "Structural delimiter boundary violation", "score": 0.85}

    return {"is_valid": True, "sanitized_prompt": prompt, "score": 0.0}
