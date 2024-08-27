from scapy.arch import get_if_raw_hwaddr
from scapy.config import conf
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import srp

from module import Module, Type
from utils.others import print_table


class DHCPDiscover(Module):

    def __init__(self):
        super().__init__("dhcp_discover",
                         ["dhcp", "discover", "rogue", "identification"],
                         "find all dhcp server in the local network"
                         )

        self.add_option("INTERFACE", "network interface", required=True, type=Type.interface)
        self.add_option("TIMEOUT", "timeout", required=True, default=3, type=Type.float)

    def run(self):
        conf.checkIPaddr = False
        fam, hw = get_if_raw_hwaddr(self.interface)

        dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                        IP(src="0.0.0.0", dst="255.255.255.255") / \
                        UDP(sport=68, dport=67) / \
                        BOOTP(chaddr=hw) / \
                        DHCP(options=[("message-type", "discover"), "end"])

        ans, unans = srp(dhcp_discover, timeout=self.timeout, multi=True, verbose=False)
        data = [[resp[Ether].src, resp[IP].src] for _, resp in ans]
        print_table(data, headers=["MAC", "IP"])
