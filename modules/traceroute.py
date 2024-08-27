import socket

from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv import sr

from module import Module, Type


class Traceroute(Module):

    def __init__(self):
        super().__init__("traceroute",
                         ["traceroute"],
                         "traceroute")

        self.add_option("RHOST", "target host", required=True, type=Type.host)
        self.add_option("TIMEOUT", "timeout", required=True, default=3, type=Type.float)
        self.add_option("MAX-TTL", "maximum time to live", required=True, default=20, type=Type.int)
        self.add_option("MODE", "mode", required=True, default="ICMP", type=Type.string, choices=["ICMP", "TCP", "UDP"])

    def print_result(self, ans, ip):
        path = []
        for i, pkt in enumerate(ans):
            path.append(pkt[1][IP].src)
            if pkt[1][IP].src == ip:
                break

        result = [path[0]]
        for i in range(1, len(path)):
            if path[i] != path[i - 1]:
                result.append(path[i])

        for i, ip in enumerate(result):
            print(i, ip)

    def icmp_traceroute(self):
        ip = socket.gethostbyname(self.rhost)
        packets = IP(dst=ip, ttl=(1, self.max_ttl)) / ICMP()
        ans, unans = sr(packets, timeout=self.timeout, verbose=False)
        self.print_result(ans, ip)

    def tcp_traceroute(self):
        ip = socket.gethostbyname(self.rhost)
        packets = IP(dst=ip, ttl=(1, self.max_ttl)) / TCP(dport=53, flags="S")
        ans, unans = sr(packets, timeout=self.timeout, verbose=False)
        self.print_result(ans, ip)

    def udp_traceroute(self):
        ip = socket.gethostbyname(self.rhost)
        packets = IP(dst=ip, ttl=(1, self.max_ttl)) / UDP(dport=53)
        ans, unans = sr(packets, timeout=self.timeout, verbose=False)
        self.print_result(ans, ip)

    def run(self):
        match self.mode:
            case "ICMP":
                self.icmp_traceroute()
            case "TCP":
                self.tcp_traceroute()
            case "UDP":
                self.udp_traceroute()
