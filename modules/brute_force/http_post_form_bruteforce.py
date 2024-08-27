import asyncio

import aiohttp

from module import Type
from modules.brute_force.bruteforce_login import HTTPBruteForceLogin, StopError


class HTTPPostFormBruteForce(HTTPBruteForceLogin):

    def __init__(self):
        super().__init__("http_post_form_bruteforce",
                         ["http", "post", "form", "brute-force", "brute", "force"],
                         "brute force login formular")

        self.add_option("DATA", "post data", required=True, default="username=^USER^&password=^PASS^", type=Type.string)
        self.add_option("FAILURE", "string that is visible on login failure", required=True, default="Login", type=Type.string)

    async def login(self, session: aiohttp.ClientSession, username: str, password: str):
        try:
            async with session.post("",
                                    data=self.data.replace("^USER^", username).replace("^PASS^", password)) as response:
                text = await response.text()
                if self.failure not in text:
                    print(f"[+] password found: {username}:{password}")
                    if self.stop_on_success:
                        raise StopError
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        if self.verbose:
            print(f"[-] incorrect credentials: {username}:{password}")
