import asyncio

import aiohttp

from modules.brute_force.bruteforce_login import HTTPBruteForceLogin, StopError


class HTTPBasicAuthBruteForce(HTTPBruteForceLogin):

    def __init__(self):
        super().__init__("http_basic_auth_bruteforce",
                         ["http", "basic", "authorization", "brute-force", "brute", "force"],
                         "brute force basic http authentication")

    async def login(self, session: aiohttp.ClientSession, username: str, password: str):
        try:
            async with session.get("", auth=aiohttp.BasicAuth(username, password)) as response:
                if response.status == 200:
                    print(f"[+] password found: {username}:{password}")
                    if self.stop_on_success:
                        raise StopError
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        if self.verbose:
            print(f"[-] incorrect credentials: {username}:{password}")
