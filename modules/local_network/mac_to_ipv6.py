from module import Module, Type


class MACToIPv6(Module):

    def __init__(self):
        super().__init__("mac_to_ipv6",
                         ["mac", "to", "ipv6", "link", "local"],
                         "convert mac address to link local ipv6 address")

        self.add_option("MAC", "mac address", required=False, type=Type.mac)

    def run(self):
        octets = self.mac.split(":")

        octets.insert(3, "ff")
        octets.insert(4, "fe")

        octets[0] = "%x" % (int(octets[0], 16) ^ 2)

        result = [octets[i] + octets[i + 1] for i in range(0, 8, 2)]
        result.insert(0, "fe80:")
        print(":".join(result))
