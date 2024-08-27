import asyncio
import os.path
import re

import aiohttp

from config import DEFAULT_USER_AGENT
from module import Module, Type
from utils.others import read_wordlist


class Fuzz(Module):

    def __init__(self):
        super().__init__("fuzz",
                         ["fuzz", "fuzzer", "fuzzing", "http", "web"],
                         "http request fuzzer")

        self.add_option("URL", "url", required=True, type=Type.string)
        self.add_option("WORDLIST", "path to a wordlist", required=True, type=Type.path)
        self.add_option("METHOD", "http method", required=True, default="get", type=Type.string, choices=["get", "post"])
        self.add_option("DATA", "post request data", required=False, type=Type.string)
        self.add_option("MATCH-CODES", "match response codes", required=False, type=Type.int_list)
        self.add_option("FILTER-CODES", "filter response codes", required=False, type=Type.int_list)
        self.add_option("MATCH-SIZE", "match response sizes (list or range)", required=False, type=Type.int_list_or_range)
        self.add_option("FILTER-SIZE", "filter response sizes (list or range)", required=False, type=Type.int_list_or_range)
        self.add_option("REGEX", "filter response with regex", required=False, type=Type.string)
        self.add_option("OPERATOR", "filter operator: and, or", required=True, default="and", type=Type.string, choices=["and", "or"])
        self.add_option("COOKIES", "cookies", required=False, type=Type.string)
        self.add_option("USER-AGENT", "user agent", required=True, default=DEFAULT_USER_AGENT, type=Type.string)
        self.add_option("TIMEOUT", "timeout", required=True, default=60, type=Type.int)
        self.add_option("RETRIES", "number of attempts after a timeout", required=True, default=3, type=Type.int)

    async def match_response_codes(self, response):
        return response.status in self.match_codes

    async def filter_response_codes(self, response):
        return response.status not in self.filter_codes

    async def match_response_size(self, response):
        return len(await response.read()) in self.match_size

    async def filter_response_size(self, response):
        return len(await response.read()) not in self.filter_size

    async def search_regex(self, response):
        return re.search(self.regex, await response.text()) is not None

    def response_filter(self):
        filters = [lambda response: True]
        if self.match_codes:
            filters.append(self.match_response_codes)
        if self.filter_codes:
            filters.append(self.filter_response_codes)
        if self.match_size:
            filters.append(self.match_response_size)
        if self.match_size:
            filters.append(self.match_response_size)
        if self.filter_size:
            filters.append(self.filter_response_size)
        if self.regex:
            filters.append(self.search_regex)

        return filters

    async def filter_and_print(self, word: str, response, response_filter):
        if self.operator == "and" and all(f(response) for f in response_filter):
            print(word.ljust(30), f"[code: {response.status}, size: {len(await response.read())}]")
        elif self.operator == "or" and any(f(response) for f in response_filter):
            print(word.ljust(30), f"[code: {response.status}, size: {len(await response.read())}]")

    async def check(self, session: aiohttp.ClientSession, word: str, response_filter: list, retries: int):
        try:
            url = self.url.replace("FUZZ", word)
            if self.method == "get":
                async with session.get(url) as response:
                    await self.filter_and_print(word, response, response_filter)
            elif self.method == "post":
                data = self.data.replace("FUZZ", word)
                async with session.post(url, data=data) as response:
                    await self.filter_and_print(word, response, response_filter)

        except aiohttp.ClientError:
            pass
        except asyncio.TimeoutError:
            if retries > 0:
                await self.check(session, word, response_filter, retries - 1)

    async def fuzz(self):
        headers = {"User-Agent": self.user_agent}
        if self.cookies:
            headers["Cookies"] = self.cookies

        response_filter = self.response_filter()

        async with aiohttp.ClientSession(headers=headers,
                                         timeout=aiohttp.ClientTimeout(self.timeout)) as session:
            await asyncio.gather(*[self.check(session, word, response_filter, self.retries) for word in read_wordlist(self.wordlist)])

    def run(self):
        if not os.path.isfile(self.wordlist):
            print("[-] wordlist does not exist")
            return
        if self.method == "get" and "FUZZ" not in self.url:
            print("[-] FUZZ not in url!")
            return
        if self.method == "post" and "FUZZ" not in self.url and "FUZZ" not in self.data:
            print("[-] FUZZ not in url and data!")
            return

        asyncio.run(self.fuzz())
