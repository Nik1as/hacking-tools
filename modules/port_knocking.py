from scapy.layers.inet import TCP, IP
from scapy.sendrecv import send
from scapy.volatile import RandShort

from module import Module, Type


class PortKnocking(Module):

    def __init__(self):
        super().__init__("port_knocking",
                         ["port", "knocking", "knock", "firewall", "filtered"],
                         "knock a sequence if of ports")

        self.add_option("RHOST", "target host", required=True, type=Type.host)
        self.add_option("SEQUENCE", "sequence of ports", required=True, default=[7000, 8000, 9000], type=Type.int_list)

    def run(self):
        for port in self.sequence:
            pkt = IP(dst=self.rhost) / TCP(sport=RandShort(), dport=port, flags="S")
            send(pkt, verbose=False)
