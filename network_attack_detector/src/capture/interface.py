import psutil
import socket
from typing import List, Optional
from src.core.models import InterfaceInfo

class CaptureInterface:
    """
    获取本机可用网卡列表，用于网络抓包或流量监控场景。
    
    依赖: pip install psutil
    """
    
    @staticmethod
    def get_interfaces(include_loopback: bool = True, only_up: bool = True) -> List[InterfaceInfo]:
        """
        获取网卡列表。
        
        Args:
            include_loopback: 是否包含回环接口（lo/127.0.0.1）
            only_up: 是否只返回已启用的网卡
            
        Returns:
            InterfaceInfo 对象列表
        """
        interfaces: List[InterfaceInfo] = []
        
        # 获取所有网卡地址信息
        addrs = psutil.net_if_addrs()
        # 获取网卡状态/统计信息
        stats = psutil.net_if_stats()
        
        for name, addr_list in addrs.items():
            ip_list: List[str] = []
            mac: Optional[str] = None
            
            for addr in addr_list:
                if addr.family == socket.AF_INET:      # IPv4
                    ip_list.append(addr.address)
                elif addr.family == socket.AF_INET6:   # IPv6
                    ip_list.append(addr.address)
                elif addr.family == psutil.AF_LINK:    # MAC 地址
                    mac = addr.address
            
            # 获取状态信息
            stat = stats.get(name)
            is_up = stat.isup if stat else False
            speed = stat.speed if stat else None
            mtu = stat.mtu if stat else None
            
            # 判断是否为回环
            is_loopback = name.lower() in ('lo', 'loopback') or any(
                ip.startswith('127.') for ip in ip_list
            )
            
            # 过滤
            if is_loopback and not include_loopback:
                continue
            if only_up and not is_up:
                continue
            
            # 尝试获取友好名称（Windows 专用）
            friendly = name
            if hasattr(psutil, 'net_if_addrs'):
                # psutil 没有直接提供友好名称，Windows 上可用 WMI 扩展
                pass
            
            info = InterfaceInfo(
                name=name,
                friendly_name=friendly,
                ip_addresses=ip_list,
                mac_address=mac,
                is_up=is_up,
                is_loopback=is_loopback,
                speed=speed,
                mtu=mtu
            )
            interfaces.append(info)
        
        return interfaces
    
    @staticmethod
    def get_default_interface() -> Optional[InterfaceInfo]:
        """
        尝试获取默认路由对应的网卡（通常是对外通信的主网卡）。
        """
        interfaces = {iface.name: iface for iface in CaptureInterface.get_interfaces()}
        
        # 通过默认路由找出口网卡
        if hasattr(psutil, "net_if_stats"):
            try:
                # Linux: 读取路由表找 default gateway
                with open('/proc/net/route', 'r') as f:
                    for line in f.readlines()[1:]:
                        parts = line.strip().split()
                        if parts[1] == '00000000':  # destination 0.0.0.0
                            iface_name = parts[0]
                            if iface_name in interfaces:
                                return interfaces[iface_name]
            except Exception:
                pass
        
        # 兜底：找一个非回环且已启用的
        for iface in interfaces.values():
            if not iface.is_loopback and iface.is_up and iface.ip_addresses:
                return iface
        return None


# ========== 使用示例 ==========
if __name__ == "__main__":
    print("=" * 60)
    print("本机所有可用网卡（不含回环）:")
    print("=" * 60)
    
    for iface in CaptureInterface.get_interfaces(include_loopback=False):
        print(f"  名称: {iface.name}")
        print(f"  IP:   {', '.join(iface.ip_addresses) or '无'}")
        print(f"  MAC:  {iface.mac_address or '无'}")
        print(f"  状态: {'UP' if iface.is_up else 'DOWN'}")
        print(f"  速率: {iface.speed} Mbps" if iface.speed else "  速率: 未知")
        print("-" * 40)
    
    default = CaptureInterface.get_default_interface()
    if default:
        print(f"\n默认出口网卡: {default}")