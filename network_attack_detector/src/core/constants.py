from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
RULES_DIR = DATA_DIR / "rules"
EXPORTS_DIR = DATA_DIR / "exports"

DEFAULT_APP_CONFIG_PATH = CONFIG_DIR / "app_config.yaml"
DEFAULT_LOGGING_CONFIG_PATH = CONFIG_DIR / "logging_config.yaml"
DEFAULT_SIGNATURE_RULES_PATH = RULES_DIR / "signature_rules.csv"
DEFAULT_BEHAVIOR_RULES_PATH = RULES_DIR / "behavior_rules.json"
DEFAULT_DATABASE_PATH = DATA_DIR / "ids.db"

SUPPORTED_MATCH_TYPES = {"content", "regex"}
DEFAULT_PAYLOAD_PREVIEW_LENGTH = 512
