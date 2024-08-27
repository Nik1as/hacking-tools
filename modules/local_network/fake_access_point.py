from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.sendrecv import sendp
from scapy.volatile import RandMAC

from module import Module, Type


class FakeAccessPoint(Module):

    def __init__(self):
        super().__init__("fake_access_point",
                         ["fake", "access", "point", "wifi"],
                         "create a fake access point")

        self.add_option("INTERFACE", "network interface", required=True, type=Type.interface)
        self.add_option("SSID", "ssid", required=True, default="Fake AP", type=Type.string)

    def run(self):
        sender_mac = RandMAC()
        pkt = (RadioTap() /
               Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac) /
               Dot11Beacon() /
               Dot11Elt(ID="SSID", info=self.ssid, len=len(self.ssid)))
        sendp(pkt, inter=0.5, iface=self.interface, loop=True)
