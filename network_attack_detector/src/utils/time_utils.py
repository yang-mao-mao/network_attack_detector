from __future__ import annotations

import time
from datetime import datetime


def now_ts() -> float:
    return time.time()


def format_ts(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

