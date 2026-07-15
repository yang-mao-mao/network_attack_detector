#!/usr/bin/env python3
"""
生成行为检测演示请求样本（端口扫描、暴力破解、高频请求）
输出格式：每行一个请求，字段以空格分隔
    timestamp src_ip dst_ip dst_port protocol [path]
示例： 1000.0 10.0.0.1 10.0.0.2 80 TCP /login
"""

import argparse
import random
import time
from typing import List


def generate_port_scan(
    src_ip: str = "10.0.0.1",
    dst_ip: str = "10.0.0.2",
    base_port: int = 20,
    num_ports: int = 15,
    start_time: float = 1000.0,
    step: float = 0.1,
) -> List[str]:
    """生成端口扫描请求：同一源IP访问同一目的IP的多个TCP端口"""
    requests = []
    for i in range(num_ports):
        port = base_port + i
        ts = start_time + i * step
        requests.append(f"{ts:.1f} {src_ip} {dst_ip} {port} TCP")
    return requests


def generate_bruteforce(
    src_ip: str = "10.0.0.3",
    dst_ip: str = "10.0.0.4",
    num_attempts: int = 12,
    start_time: float = 2000.0,
    step: float = 0.05,
) -> List[str]:
    """生成暴力破解请求：同一源IP访问登录路径"""
    requests = []
    users = ["admin", "root", "user", "test", "guest", "demo"]
    for i in range(num_attempts):
        user = random.choice(users)
        path = f"/login?username={user}&password=123456"
        ts = start_time + i * step
        requests.append(f"{ts:.1f} {src_ip} {dst_ip} 80 HTTP {path}")
    return requests


def generate_high_frequency(
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.0.6",
    num_requests: int = 110,
    start_time: float = 3000.0,
    step: float = 0.01,
) -> List[str]:
    """生成高频请求：同一源IP大量访问API"""
    requests = []
    for i in range(num_requests):
        path = f"/api/data?page={i % 10}"
        ts = start_time + i * step
        requests.append(f"{ts:.1f} {src_ip} {dst_ip} 80 HTTP {path}")
    return requests


def main():
    parser = argparse.ArgumentParser(description="生成行为检测演示请求")
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="输出文件路径（默认打印到标准输出）"
    )
    args = parser.parse_args()

    # 生成三类请求并混合
    requests = (
        generate_port_scan()
        + generate_bruteforce()
        + generate_high_frequency()
    )
    random.shuffle(requests)  # 混合流量模拟真实场景

    # 输出
    output_lines = "\n".join(requests)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_lines)
        print(f"已生成 {len(requests)} 条请求，保存至 {args.output}")
    else:
        print(output_lines)


if __name__ == "__main__":
    main()