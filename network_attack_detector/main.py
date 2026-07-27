from __future__ import annotations

import argparse
from pathlib import Path

from src.detection.behavior_engine import BehaviorEngine
from src.detection.detection_manager import DetectionManager
from src.detection.signature_engine import SignatureEngine
from src.parser.packet_parser import PacketParser
from src.rules.rule_loader import RuleLoader
from src.storage.database import Database
from src.storage.alert_repository import AlertRepository
from src.storage.rule_repository import RuleRepository
from src.storage.packet_repository import PacketRepository
import yaml


PROJECT_ROOT = Path(__file__).resolve().parent


def run_self_check() -> int:
    rules_dir = PROJECT_ROOT / "data" / "rules"
    
    
    #从配置文件中读取数据
    config_dir=PROJECT_ROOT/"config"
    app_config_file=config_dir/"app_config.yaml"
    with app_config_file.open() as file:
        config=yaml.safe_load(file)
    paths=config.get('paths')
    database_path=paths.get('database')
    db_path=PROJECT_ROOT/database_path
    
    #数据库搭建
    database=Database(db_path)
    database.initialize()
    
    #使保存模块与数据库关联
    alert_repository=AlertRepository(database)
    
    packet_repository=PacketRepository(database)
    
    #加载规则
    loader = RuleLoader()
    signature_rules = loader.load_signature_rules(rules_dir / "signature_rules.csv")
    behavior_rules = loader.load_behavior_rules(rules_dir / "behavior_rules.json")
    
    rule_repository=RuleRepository(signature_rules,behavior_rules)
    #数据包
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
    packet_repository.save(packet)
    
    #检测引擎
    manager = DetectionManager(
        signature_engine=SignatureEngine(rule_repository.list_signature_rules(enabled_only=True)),
        behavior_engine=BehaviorEngine(rule_repository.list_behavior_rules(enabled_only=True)),
    )
    result = manager.detect(packet)
    
    for alert in result.alerts:
        alert_repository.save(alert)
    
    recent_packets=packet_repository.list_recent(5)
    recent_alerts=alert_repository.list_recent(5) 
    
    
    print("Self-check summary")
    print(f"Signature rules: {len(signature_rules)}")
    print(f"Behavior rules: {len(behavior_rules)}")
    print(f"Packet protocol: {packet.protocol}")
    print(f"Alerts: {len(result.alerts)}")
    print(f"Recent packets in DB: {len(recent_packets)}")
    print(f"Recent alerts in DB: {len(recent_alerts)}")
    for alert in result.alerts:
        print(f"- [{alert.level.value}] {alert.category.value}: {alert.evidence}")

    return 0 if result.alerts and recent_alerts and recent_packets else 1


def run_ui(load_demo: bool = False) -> int:
    try:
        from src.ui.main_window import main as ui_main
    except ModuleNotFoundError as exc:
        if exc.name == "PyQt6":
            print("PyQt6 is not installed. Install project requirements before launching UI.")
            return 1
        raise

    ui_main(load_demo=load_demo)
    return 0


def run_generate_demo_data() -> int:
    from src.demo_data import write_demo_files

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


def main() -> int:
    arg_parser = argparse.ArgumentParser(
        description="Network attack detector project scaffold."
    )
    mode_group = arg_parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--self-check",
        action="store_true",
        help="Run a minimal parser and detection pipeline check.",
    )
    mode_group.add_argument(
        "--ui",
        action="store_true",
        help="Launch the PyQt6 user interface.",
    )
    mode_group.add_argument(
        "--ui-demo",
        action="store_true",
        help="Launch the PyQt6 UI with reproducible demo traffic preloaded.",
    )
    mode_group.add_argument(
        "--generate-demo-data",
        action="store_true",
        help="Write reproducible demo traffic JSON files under data/samples.",
    )
    args = arg_parser.parse_args()

    if args.self_check:
        return run_self_check()
    if args.ui:
        return run_ui()
    if args.ui_demo:
        return run_ui(load_demo=True)
    if args.generate_demo_data:
        return run_generate_demo_data()

    print("Project scaffold is ready. Run with --self-check, --ui, or --ui-demo.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
