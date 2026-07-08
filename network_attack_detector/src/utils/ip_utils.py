from __future__ import annotations

import ipaddress


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_private_ip(value: str) -> bool:
    return ipaddress.ip_address(value).is_private

