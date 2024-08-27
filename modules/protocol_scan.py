from scapy.config import conf
from scapy.layers.inet import IP
from scapy.sendrecv import sr

from module import Module, Type


class ProtocolScan(Module):

    def __init__(self):
        super().__init__("protocol_scan",
                         ["ip", "protocol", "scan"],
                         "find supported layer 4 protocols with the next header field in the IP header")

        self.add_option("RHOST", "target host", required=True, type=Type.host)
        self.add_option("TIMEOUT", "timeout", required=True, default=3, type=Type.float)

    def run(self):
        protocols = dict(conf.protocols)

        packets = IP(dst=self.rhost, proto=(0, 255)) / "SCAPY"
        ans, unans = sr(packets, timeout=self.timeout, retry=False, verbose=False)

        for pkt in unans:
            protocol = pkt[IP].proto
            print(f"{protocol:<4}{protocols.get(protocol, '')}")
