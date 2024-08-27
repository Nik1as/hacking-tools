import re

from scapy.layers import http
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.sendrecv import sniff

from module import Module, Type


def packet_sniffed(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(http.HTTPRequest):
        print(pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path)
        print(f"src: {pkt[IP].src}:{pkt[TCP].sport}\tdest: {pkt[IP].dst}:{pkt[TCP].dport}")

        contents = pkt[Raw].load

        for keyword in ("email", "user", "pass", "login"):
            for line in contents.split("\n"):
                if re.match(keyword, line, re.IGNORECASE):
                    print()


class PacketSniffer(Module):

    def __init__(self):
        super().__init__("packet_sniffer",
                         ["network", "packet", "sniffer", "sniff"],
                         "sniff network packets")

        self.add_option("INTERFACE", "network interface", required=True, type=Type.interface)

    def run(self):
        try:
            sniff(iface=self.interface, store=False, prn=packet_sniffed)
        except KeyboardInterrupt:
            pass
