import asyncio
import re
from random import choice
from urllib.parse import urlparse, parse_qs, ParseResult, urlencode, urljoin

import aiohttp
import bs4.element
from bs4 import BeautifulSoup

from utils.others import read_wordlist
from utils.regex import HTTP_REGEX

user_agents = list(read_wordlist("data/user-agents.txt"))


def random_user_agent():
    return choice(user_agents)


def get_forms(html: str):
    soup = BeautifulSoup(html, "html.parser")
    return soup.findAll("form")


def parse_form(form: bs4.element.Tag):
    method = form.get("method", "get")
    action = form.get("action", "/")
    args = []
    for input_tag in form.findAll("input"):
        name = input_tag.get("name")
        if name is not None:
            args.append(name)
    return method, action, args


def change_url_param_value(url: str, param: str, new_value: str):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param][0] = new_value
    return ParseResult(scheme=parsed.scheme, netloc=parsed.hostname, path=parsed.path, params=parsed.params, query=urlencode(params),
                       fragment=parsed.fragment).geturl()


def url_parameters(url: str):
    parsed = urlparse(url)
    return list(parse_qs(parsed.query).keys())


def url_join(url: str, *paths: str) -> str:
    result = url.rstrip("/")
    for path in paths:
        result += "/" + path.lstrip("./").strip("/")
    return result


def get_url(host: str, port: int, targeturi: str = None) -> str:
    base_url = f"http://{host}:{port}"
    if targeturi is None:
        return base_url
    return url_join(base_url, targeturi)


def web_directories_to_tree(directories):
    def display_tree(tree, indent=0):
        for key, value in tree.items():
            print("  " * indent + key)
            display_tree(value, indent + 1)

    tree = {}

    for path in directories:
        current_node = tree
        components = path.split("/")

        for component in components:
            if component not in current_node:
                current_node[component] = {}

            current_node = current_node[component]
    display_tree(tree)


async def crawl(session: aiohttp.ClientSession, curr_url: str, depth: int, max_depth: int, callback: callable):
    if depth > max_depth:
        return

    try:
        async with session.get(curr_url) as response:
            if response.status != 200:
                return

            text = await response.text()
            soup = BeautifulSoup(text, "html.parser")
            callback(curr_url, soup)

            urls = []
            for link in soup.find_all("a"):
                href = link.get("href")
                if href is not None:
                    new_url = href
                    if re.match(HTTP_REGEX, href):
                        curr_domain = urlparse(href).netloc
                        if curr_domain != urlparse(curr_url).netloc:
                            continue
                    else:
                        new_url = urljoin(curr_url, href)
                    urls.append(new_url)

            await asyncio.gather(*[crawl(session, new_url, depth + 1, max_depth, callback, )
                                   for new_url in urls])
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass


async def crawler(url: str, max_depth: int, timeout: int, callback: callable, headers: dict = None):
    headers = headers or dict()
    async with aiohttp.ClientSession(headers=headers,
                                     timeout=aiohttp.ClientTimeout(timeout)) as session:
        await crawl(session, url, 1, max_depth, callback)
