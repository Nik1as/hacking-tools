import socket

from module import Module, Type


class HostToIP(Module):

    def __init__(self):
        super().__init__("host_to_ip",
                         ["host", "to", "ip"],
                         "host to ip")
        self.add_option("RHOST", "target host", required=True, type=Type.host)

    def run(self):
        try:
            print("IPv4:", socket.getaddrinfo(self.rhost, None, socket.AF_INET)[0][4][0])
        except socket.gaierror:
            pass
        try:
            print("IPv6:", socket.getaddrinfo(self.rhost, None, socket.AF_INET6)[0][4][0])
        except socket.gaierror:
            pass
