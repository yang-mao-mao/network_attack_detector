from __future__ import annotations

import socket
import subprocess
import sys
from collections.abc import Callable
from typing import Any

from src.core.models import InterfaceInfo

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

try:
    from scapy.all import conf as scapy_conf
except ImportError:  # pragma: no cover
    scapy_conf = None


class CaptureInterface:
    def list_interfaces(self) -> list[str]:
        raise NotImplementedError

    def start_capture(self, interface: str, packet_callback: Callable[[Any], None]) -> None:
        raise NotImplementedError

    def stop_capture(self) -> None:
        raise NotImplementedError

    @staticmethod
    def get_interfaces(
        include_loopback: bool = True,
        only_up: bool = True,
    ) -> list[InterfaceInfo]:
        interfaces = CaptureInterface._get_scapy_interfaces(
            include_loopback=include_loopback,
            only_up=only_up,
        )
        if interfaces:
            return interfaces

        if psutil is not None:
            try:
                return CaptureInterface._get_psutil_interfaces(
                    include_loopback=include_loopback,
                    only_up=only_up,
                )
            except Exception:
                pass

        interfaces = CaptureInterface._get_windows_netsh_interfaces(
            include_loopback=include_loopback,
            only_up=only_up,
        )
        if interfaces:
            return interfaces

        return CaptureInterface._get_socket_interfaces(
            include_loopback=include_loopback,
        )

    @staticmethod
    def _get_scapy_interfaces(
        include_loopback: bool = True,
        only_up: bool = True,
    ) -> list[InterfaceInfo]:
        if scapy_conf is None:
            return []

        state_by_name = CaptureInterface._get_windows_interface_states()
        interfaces: list[InterfaceInfo] = []

        try:
            scapy_interfaces = list(scapy_conf.ifaces.values())
        except Exception:
            return []

        for iface in scapy_interfaces:
            network_name = str(
                getattr(iface, "network_name", None)
                or getattr(iface, "name", "")
                or ""
            )
            if not network_name:
                continue

            friendly_name = str(getattr(iface, "name", "") or network_name)
            ip = str(getattr(iface, "ip", "") or "")
            mac = str(getattr(iface, "mac", "") or "") or None
            ip_addresses = [ip] if ip else []

            lowered_name = friendly_name.lower()
            lowered_network = network_name.lower()
            is_loopback = (
                "loopback" in lowered_name
                or lowered_network.endswith("npf_loopback")
                or ip.startswith("127.")
            )
            if is_loopback and not include_loopback:
                continue

            if friendly_name in state_by_name:
                is_up = state_by_name[friendly_name]
            else:
                is_up = bool(ip_addresses) or is_loopback

            if only_up and not is_up:
                continue

            interfaces.append(
                InterfaceInfo(
                    name=network_name,
                    friendly_name=friendly_name,
                    ip_addresses=ip_addresses,
                    mac_address=mac,
                    is_up=is_up,
                    is_loopback=is_loopback,
                    speed=None,
                    mtu=None,
                )
            )

        return interfaces

    @staticmethod
    def _get_psutil_interfaces(
        include_loopback: bool = True,
        only_up: bool = True,
    ) -> list[InterfaceInfo]:
        if psutil is None:
            return []

        interfaces: list[InterfaceInfo] = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for name, addr_list in addrs.items():
            ip_addresses: list[str] = []
            mac_address: str | None = None

            for addr in addr_list:
                family_name = getattr(addr.family, "name", str(addr.family))
                if family_name in {"AF_INET", "AF_INET6"}:
                    ip_addresses.append(addr.address)
                elif family_name == "AF_LINK" or addr.family == getattr(psutil, "AF_LINK", None):
                    mac_address = addr.address

            stat = stats.get(name)
            is_up = stat.isup if stat else False
            speed = stat.speed if stat else None
            mtu = stat.mtu if stat else None
            is_loopback = name.lower() in {"lo", "loopback"} or any(
                ip.startswith("127.") for ip in ip_addresses
            )

            if is_loopback and not include_loopback:
                continue
            if only_up and not is_up:
                continue

            interfaces.append(
                InterfaceInfo(
                    name=name,
                    friendly_name=name,
                    ip_addresses=ip_addresses,
                    mac_address=mac_address,
                    is_up=is_up,
                    is_loopback=is_loopback,
                    speed=speed,
                    mtu=mtu,
                )
            )

        return interfaces

    @staticmethod
    def _get_windows_interface_states() -> dict[str, bool]:
        if not sys.platform.startswith("win"):
            return {}

        try:
            completed = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                check=True,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
            )
        except Exception:
            return {}

        states: dict[str, bool] = {}
        for line in completed.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5 or not parts[0].isdigit():
                continue

            state = parts[3].lower()
            friendly_name = " ".join(parts[4:])
            states[friendly_name] = state == "connected"

        return states

    @staticmethod
    def _get_windows_netsh_interfaces(
        include_loopback: bool = True,
        only_up: bool = True,
    ) -> list[InterfaceInfo]:
        if not sys.platform.startswith("win"):
            return []

        try:
            socket_names = dict(socket.if_nameindex())
        except OSError:
            socket_names = {}

        try:
            completed = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "interfaces"],
                check=True,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
            )
        except Exception:
            return []

        interfaces: list[InterfaceInfo] = []
        for line in completed.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5 or not parts[0].isdigit():
                continue

            index = int(parts[0])
            state = parts[3].lower()
            friendly_name = " ".join(parts[4:])
            socket_name = socket_names.get(index, friendly_name)
            is_up = state == "connected"
            lowered_friendly = friendly_name.lower()
            lowered_socket = socket_name.lower()
            is_loopback = (
                "loopback" in lowered_friendly
                or lowered_socket.startswith("loopback")
            )

            if is_loopback and not include_loopback:
                continue
            if only_up and not is_up:
                continue

            interfaces.append(
                InterfaceInfo(
                    name=socket_name,
                    friendly_name=friendly_name,
                    ip_addresses=[],
                    mac_address=None,
                    is_up=is_up,
                    is_loopback=is_loopback,
                    speed=None,
                    mtu=None,
                )
            )

        return interfaces

    @staticmethod
    def _get_socket_interfaces(
        include_loopback: bool = True,
    ) -> list[InterfaceInfo]:
        try:
            names = socket.if_nameindex()
        except OSError:
            return []

        interfaces: list[InterfaceInfo] = []
        for _, name in names:
            lowered = name.lower()
            is_loopback = lowered in {"lo", "loopback"} or "loopback" in lowered
            if is_loopback and not include_loopback:
                continue
            interfaces.append(
                InterfaceInfo(
                    name=name,
                    friendly_name=name,
                    ip_addresses=[],
                    mac_address=None,
                    is_up=True,
                    is_loopback=is_loopback,
                    speed=None,
                    mtu=None,
                )
            )
        return interfaces
