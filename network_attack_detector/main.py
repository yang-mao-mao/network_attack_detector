from __future__ import annotations

import argparse
from pathlib import Path

from src.detection.behavior_engine import BehaviorEngine
from src.detection.detection_manager import DetectionManager
from src.detection.signature_engine import SignatureEngine
from src.parser.packet_parser import PacketParser
from src.rules.rule_loader import RuleLoader


PROJECT_ROOT = Path(__file__).resolve().parent


def run_self_check() -> int:
    rules_dir = PROJECT_ROOT / "data" / "rules"
    loader = RuleLoader()
    signature_rules = loader.load_signature_rules(rules_dir / "signature_rules.csv")
    behavior_rules = loader.load_behavior_rules(rules_dir / "behavior_rules.json")

    parser = PacketParser()
    raw_request = (
        b"GET /search?q=1%20union%20select%20password%20from%20users HTTP/1.1\r\n"
        b"Host: demo.local\r\n"
        b"User-Agent: self-check\r\n"
        b"\r\n"
    )
    packet = parser.parse_http_bytes(
        raw_request,
        src_ip="192.168.1.10",
        dst_ip="192.168.1.20",
        src_port=51000,
        dst_port=80,
    )

    manager = DetectionManager(
        signature_engine=SignatureEngine(signature_rules),
        behavior_engine=BehaviorEngine(behavior_rules),
    )
    result = manager.detect(packet)

    print("Self-check summary")
    print(f"Signature rules: {len(signature_rules)}")
    print(f"Behavior rules: {len(behavior_rules)}")
    print(f"Packet protocol: {packet.protocol}")
    print(f"Alerts: {len(result.alerts)}")
    for alert in result.alerts:
        print(f"- [{alert.level.value}] {alert.category.value}: {alert.evidence}")

    return 0 if result.alerts else 1


def main() -> int:
    arg_parser = argparse.ArgumentParser(
        description="Network attack detector project scaffold."
    )
    arg_parser.add_argument(
        "--self-check",
        action="store_true",
        help="Run a minimal parser and detection pipeline check.",
    )
    args = arg_parser.parse_args()

    if args.self_check:
        return run_self_check()

    print("Project scaffold is ready. Run with --self-check to validate the pipeline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

