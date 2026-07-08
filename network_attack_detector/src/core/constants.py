from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
RULES_DIR = DATA_DIR / "rules"
EXPORTS_DIR = DATA_DIR / "exports"

SUPPORTED_MATCH_TYPES = {"content", "regex"}
DEFAULT_PAYLOAD_PREVIEW_LENGTH = 512

