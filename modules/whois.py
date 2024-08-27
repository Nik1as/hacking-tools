import whois

from module import Module, Type


class Whois(Module):

    def __init__(self):
        super().__init__("whois",
                         ["whois", "domain"],
                         "get information about a domain with whois")

        self.add_option("RHOST", "target host", required=True, type=Type.host)

    def run(self):
        try:
            response = whois.whois(self.rhost)

            for line in response.text.splitlines():
                if line and not line.startswith("%"):
                    print(line)
        except whois.parser.PywhoisError:
            print("[-] host not found")
