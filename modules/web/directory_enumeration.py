import asyncio
import os.path
from itertools import chain

import aiohttp

from config import DEFAULT_USER_AGENT, WHITESPACE_FILL
from module import Module, Type
from utils.others import read_wordlist
from utils.web import url_join, web_directories_to_tree


class DirectoryEnumeration(Module):

    def __init__(self):
        super().__init__("directory_enumeration",
                         ["directory", "directories", "enumerate", "enumeration", "brute-force"],
                         "find directories of a website")

        self.add_option("URL", "target url", required=True, type=Type.string)
        self.add_option("WORDLIST", "path to a wordlist of directories", required=True, default="data/wordlists/directories.txt", type=Type.path)
        self.add_option("EXTENSIONS", "list of file extensions e.g. html,php", required=False, type=Type.string_list)
        self.add_option("BLACKLIST", "list of status codes to exclude", required=True, default=[404], type=Type.int_list)
        self.add_option("RECURSIVE", "search recursive", required=True, default=False, type=Type.bool)
        self.add_option("TIMEOUT", "timeout", required=True, default=60, type=Type.int)
        self.add_option("COOKIES", "cookies", required=False, type=Type.string)
        self.add_option("USER-AGENT", "user agent", required=True, default=DEFAULT_USER_AGENT, type=Type.string)
        self.add_option("FULL-URL", "print the full url", required=True, default=False, type=Type.bool)
        self.add_option("OUTPUT", "output file", required=False, type=Type.path)
        self.add_option("RETRIES", "number of attempts after a timeout", required=True, default=3, type=Type.int)

    def get_paths(self, words: list[str], curr_path: str):
        paths = []
        for word in words:
            paths.append((f"{curr_path}/{word}", True))

            if self.extensions is not None:
                for ext in self.extensions:
                    paths.append((f"{curr_path}/{word}.{ext}", False))
        return paths

    async def check_path(self, session, curr_path: str, is_dir: bool, words: list[str], retries: int):
        try:
            async with session.get(curr_path) as response:
                if response.status in self.blacklist:
                    return []

                if self.full_url:
                    print(f"{url_join(self.url, curr_path).ljust(WHITESPACE_FILL)}(Status: {response.status})")
                else:
                    print(f"/{curr_path.lstrip("/").ljust(WHITESPACE_FILL)}(Status: {response.status})")

                paths = [curr_path]
                if self.recursive and is_dir:
                    results = await asyncio.gather(*[self.check_path(session, path, is_dir, words, self.retries)
                                                     for path, is_dir in self.get_paths(words, curr_path)],
                                                   return_exceptions=True)
                    paths.extend(chain(*results))
                return paths
        except aiohttp.ClientError:
            pass
        except asyncio.TimeoutError:
            if retries > 0:
                return await self.check_path(session, curr_path, is_dir, words, retries - 1)
        return []

    async def main(self):
        words = list(read_wordlist(self.wordlist))
        found_directories = []

        headers = {"User-Agent": self.user_agent}
        if self.cookies:
            headers["Cookies"] = self.cookies

        try:
            async with aiohttp.ClientSession(base_url=self.url,
                                             headers=headers,
                                             timeout=aiohttp.ClientTimeout(self.timeout)) as session:
                results = await asyncio.gather(*[self.check_path(session, path, is_dir, words, self.retries)
                                                 for path, is_dir in self.get_paths(words, "")],
                                               return_exceptions=True)
                found_directories.extend(chain(*results))
        except KeyboardInterrupt:
            pass

        if self.recursive:
            web_directories_to_tree(found_directories)

        if self.output:
            with open(self.output, "w") as f:
                if self.full_url:
                    f.write("\n".join(map(lambda x: url_join(self.url, x), found_directories)))
                else:
                    f.write("\n".join(found_directories))

    def run(self):
        if not os.path.isfile(self.wordlist):
            print("[-] wordlist does not exist")
            return

        asyncio.run(self.main())
