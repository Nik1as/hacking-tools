import asyncio
import os.path
from urllib.parse import urlparse

import aiohttp

from config import DEFAULT_USER_AGENT, WHITESPACE_FILL
from module import Module, Type
from utils.others import read_wordlist


class SubdomainEnumerationVHost(Module):

    def __init__(self):
        super().__init__("subdomain_enumeration_vhost",
                         ["subdomain", "subdomains", "enumeration", "enumerate", "vhost"],
                         "find subdomains")

        self.add_option("URL", "target url", required=True, type=Type.host)
        self.add_option("WORDLIST", "path to a wordlist of subdomains", required=True, default="data/wordlists/subdomains.txt", type=Type.path)
        self.add_option("TIMEOUT", "timeout", required=True, default=60, type=Type.int)
        self.add_option("RETRIES", "number of attempts after a timeout", required=True, default=3, type=Type.int)
        self.add_option("USER-AGENT", "user agent", required=True, default=DEFAULT_USER_AGENT, type=Type.string)

    async def check_subdomain(self, session: aiohttp.ClientSession, subdomain: str, retries: int):
        domain = f"{subdomain}.{urlparse(self.url).netloc}"
        try:
            async with session.get(self.url, headers={"Host": domain, "User-Agent": self.user_agent}) as response:
                print(f"[+] {domain.ljust(WHITESPACE_FILL)}(Status: {response.status})")
        except asyncio.TimeoutError:
            if retries > 0:
                await self.check_subdomain(session, subdomain, retries - 1)
        except:
            pass

    async def main(self):
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
            await asyncio.gather(*[self.check_subdomain(session, subdomain, self.retries) for subdomain in read_wordlist(self.wordlist)])

    def run(self):
        if not os.path.isfile(self.wordlist):
            print("[-] wordlist does not exist")
            return

        asyncio.run(self.main())
