"""Central configuration. Every tunable lives here, overridable by environment variable.

Why: before, MOCK_UPSTREAM lived in main.py, the canary in output_guards.py and
DB_PATH in database.py. Changing behaviour meant hunting through files.
"""
import os
from pathlib import Path

# Project root = the folder that contains `app/`. Using an absolute path means the
# gateway and the dashboard always read the SAME telemetry.db, wherever you run from.
BASE_DIR = Path(__file__).resolve().parent.parent

DB_PATH = os.getenv("FIREWALL_DB_PATH", str(BASE_DIR / "data" / "telemetry.db"))

# --- Upstream LLM -----------------------------------------------------------
MOCK_UPSTREAM = os.getenv("FIREWALL_MOCK_UPSTREAM", "true").lower() == "true"
UPSTREAM_URL = os.getenv("FIREWALL_UPSTREAM_URL", "http://localhost:11434/v1/chat/completions")
UPSTREAM_TIMEOUT_S = float(os.getenv("FIREWALL_UPSTREAM_TIMEOUT_S", "30"))

# --- Canary -----------------------------------------------------------------
# A secret planted in the system prompt. If it ever shows up in a reply, the model
# has leaked its instructions. In real use, set a random value via environment.
CANARY_TOKEN = os.getenv("FIREWALL_CANARY_TOKEN", "CANARY_SEC_TOKEN_9981")
PLANT_CANARY = os.getenv("FIREWALL_PLANT_CANARY", "true").lower() == "true"

# --- Telemetry --------------------------------------------------------------
PROMPT_SNIPPET_CHARS = 120
