import enum
import socket

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp


class Protocol(enum.Enum):
    TCP = "tcp",
    UDP = "udp"


def get_mac(ip: str, timeout: float):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = srp(broadcast / arp_request, timeout=timeout, verbose=False)[0]
    return ans[0][1].hwsrc


def get_service_by_port(port: int, protocol: Protocol = Protocol.TCP) -> str:
    try:
        return socket.getservbyport(port, protocol.value[0]) + "?"
    except OSError:
        return "unknown"
