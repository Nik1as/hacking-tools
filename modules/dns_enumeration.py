import asyncio

import aiodns

from module import Module, Type

RECORD_TYPES = ["A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT"]


class DNSEnumeration(Module):

    def __init__(self):
        super().__init__("dns_enumeration",
                         ["dns", "domain", "name", "system", "enumeration"],
                         "dns enumeration")
        self.add_option("RHOST", "target host", required=True, type=Type.host)

    def run(self):
        asyncio.run(self.enumerate_dns())

    async def enumerate_dns(self):
        resolver = aiodns.DNSResolver()
        await asyncio.gather(*[self.query(resolver, record) for record in RECORD_TYPES])

    async def query(self, resolver: aiodns.DNSResolver, record: str):
        try:
            results = await resolver.query(self.rhost, record)
            if not isinstance(results, list):
                results = [results]
            if not results:
                return
            print(record)
            for result in results:
                match record:
                    case "A" | "AAAA":
                        print(result.host)
                    case "CNAME":
                        print(result.cname)
                    case "MX":
                        print(result.host)
                    case "NS":
                        print(result.host)
                    case "PTR":
                        print(result.name)
                    case "SOA":
                        print(result.nsname, result.hostmaster)
                    case "SRV":
                        print(result.host, result.port)
                    case "TXT":
                        print(result.text)
                    case _:
                        print(result)
        except aiodns.error.DNSError:
            pass
