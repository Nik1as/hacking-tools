from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr

from module import Module, Type


class PingSweeping(Module):

    def __init__(self):
        super().__init__("ping_sweeping",
                         ["ping", "sweeping", "network", "discover", "icmp"],
                         "find devices in your network")

        self.add_option("RHOSTS", "target hosts", required=True, type=Type.host)
        self.add_option("TIMEOUT", "timeout", required=True, default=3, type=Type.float)

    def run(self):
        packets = IP(dst=self.rhosts) / ICMP()
        ans, unans = sr(packets, timeout=self.timeout, verbose=False)

        for probe, response in ans:
            print(f"{response[IP].src} is alive")
