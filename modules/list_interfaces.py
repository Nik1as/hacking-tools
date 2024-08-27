from scapy.config import conf

from module import Module


class ListInterfaces(Module):

    def __init__(self):
        super().__init__("list_interfaces",
                         ["interfaces", "list", "network"],
                         "list network interfaces")

    def run(self):
        print(conf.ifaces)
