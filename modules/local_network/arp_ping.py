import json

from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp

from module import Module, Type
from utils.others import print_table


class ARPPing(Module):

    def __init__(self):
        super().__init__("arp_ping",
                         ["arp", "ping", "discover", "local", "network"],
                         "discover hosts in the local network",
                         [
                             "https://maclookup.app/downloads/json-database"
                         ])

        self.add_option("RHOSTS", "target hosts", required=True, type=Type.host)
        self.add_option("TIMEOUT", "timeout", required=True, default=3, type=Type.float)

    def run(self):
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.rhosts), timeout=self.timeout, verbose=False)

        with open("data/mac-vendors.json") as f:
            mac_vendors = json.load(f)

        table = []
        for pkt in sorted(ans, key=lambda x: tuple(map(int, x[1][ARP].psrc.split(".")))):
            mac = pkt[1][Ether].src
            mac_prefix = mac[:8]
            vendor = ""

            for entry in mac_vendors:
                if entry["macPrefix"] == mac_prefix:
                    vendor = entry["vendorName"]
                    break

            table.append([pkt[1][ARP].psrc, mac, vendor])

        print_table(table, headers=["IP", "MAC", "VENDOR"])
