import asyncio
import os.path

import aiohttp
import requests
from bs4 import BeautifulSoup

from config import DEFAULT_USER_AGENT
from module import Module, Type
from utils.others import read_wordlist
from utils.web import get_url


class WordpressScan(Module):

    def __init__(self):
        super().__init__("wordpress_scan",
                         ["wordpress", "scanner", "wp", "website"],
                         "scan a wordpress website")

        self.add_option("RHOST", "target host", required=True, type=Type.host)
        self.add_option("RPORT", "target port", required=True, default=80, type=Type.int)
        self.add_option("TARGETURI", "target uri", required=True, default="/", type=Type.string)
        self.add_option("USER-IDS", "list of user ids", required=True, default=list(range(100)), type=Type.int_list_or_range)
        self.add_option("TIMEOUT", "timeout", required=True, default=60, type=Type.int)
        self.add_option("USER-AGENT", "user agent", required=True, default=DEFAULT_USER_AGENT, type=Type.string)

    async def get_version(self, session):
        async with session.get("/") as response:
            html = await response.text()

            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all("meta", {"name": "generator"}):
                if tag.has_attr("content"):
                    return "Version", [tag["content"]]

    async def enumerate_users(self, session):
        results = []
        for user_id in self.user_ids:
            async with session.get(f"/?author={user_id}") as response:
                html = await response.text()
                name = BeautifulSoup(html, "html.parser").find("title").text
                if response.status == 200 or 300 <= response.status <= 399:
                    results.append(f"[+] found user {name} with id {user_id}")
        return "Users", results

    async def check_plugin(self, session, plugin):
        async with session.get(f"/wp-content/plugins/{plugin}") as response:
            if response.status != 404:
                return plugin.strip("/")

    async def enumerate_plugins(self, session):
        plugins = read_wordlist("data/wordpress-plugins.txt")

        results = await asyncio.gather(*[self.check_plugin(session, plugin) for plugin in plugins])
        results = list(filter(lambda x: x is not None, results))
        return "Plugins", results

    async def check_xmlrpc(self, session):
        async with session.get("/xml-rpc.php") as response:
            if response.status >= 400:
                return "XML-RPC", ["enabled"]
        return "XML-RPC", ["disabled"]

    async def scan(self):
        async with aiohttp.ClientSession(get_url(self.rhost, self.rport, self.targeturi),
                                         headers={"User-Agent": self.user_agent},
                                         timeout=aiohttp.ClientTimeout(self.timeout)) as session:
            results = await asyncio.gather(*[self.get_version(session),
                                             self.enumerate_users(session),
                                             self.enumerate_plugins(session),
                                             self.check_xmlrpc(session)])
            for heading, info in results:
                if info:
                    print("=====", heading, "=====")
                    print("\n".join(info))

    def run(self):
        if not os.path.isfile("data/wordpress-plugins.txt"):
            plugins = []
            response = requests.get("http://plugins.svn.wordpress.org", headers={"User-Agent": DEFAULT_USER_AGENT})
            soup = BeautifulSoup(response.text, "html.parser")
            for link in soup.find_all("a"):
                plugins.append(link.text)

            with open("data/wordpress-plugins.txt", "w") as f:
                f.write("\n".join(plugins))

        asyncio.run(self.scan())
