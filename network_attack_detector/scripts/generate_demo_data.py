from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.demo_data import write_demo_files


def main() -> int:
    summary = write_demo_files()
    print("Demo data generated")
    print(f"Traffic file: {summary['traffic_path']}")
    print(f"Summary file: {summary['summary_path']}")
    print(f"Packets: {summary['packet_count']}")
    print(f"Matched packets: {summary['matched_packet_count']}")
    print(f"Alerts: {summary['alert_count']}")
    for category, count in summary["alerts_by_category"].items():
        print(f"- {category}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
