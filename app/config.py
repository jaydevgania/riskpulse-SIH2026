from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

DATABASE_PATH = Path(
    os.getenv("RISKPULSE_DATABASE_URL", str(DATA_DIR / "riskpulse.db"))
)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

APP_NAME = "RiskPulse"
APP_VERSION = "1.0.0"
