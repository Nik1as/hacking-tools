from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sniff

from module import Module, Type


def mac(ip: str):
    arp_request = ARP(pdst=ip)
    br = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_br = br / arp_request
    list_1 = srp(arp_req_br, timeout=5, verbose=False)[0]
    return list_1[0][1].hwsrc


def sniffed(packet):
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        real_mac = mac(packet[ARP].psrc)
        response_mac = packet[ARP].hwsrc
        if real_mac != response_mac:
            print(f"ARP spoofing detected: real-MAC: {real_mac} and fake-MAC: {response_mac}")


class ARPSpoofDetect(Module):

    def __init__(self):
        super().__init__("arp_spoof_detect",
                         ["arp", "spoof", "spoofing", "poisoning", "detect"],
                         "detect arp spoofing")
        self.add_option("INTERFACE", "network interface", required=True, type=Type.interface)

    def run(self):
        try:
            sniff(iface=self.interface, store=False, prn=sniffed)
        except KeyboardInterrupt:
            pass
