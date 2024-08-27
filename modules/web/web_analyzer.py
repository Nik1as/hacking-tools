import asyncio
import hashlib
import json
import re
from urllib.parse import urlparse, urljoin

import requests

from config import DEFAULT_USER_AGENT
from module import Module, Type
from utils.regex import HTML_COMMENT_REGEX, EMAIL_REGEX
from utils.web import parse_form, crawler

INTERESTING_HEADERS = ["Server", "X-Powered-By", "PHP", "X-Version", "X-Runtime", "X-AspNet-Version"]


class WebAnalyzer(Module):

    def __init__(self):
        super().__init__("web_analyzer",
                         ["web", "analyzer"],
                         "analyze a website")

        self.add_option("URL", "url", required=True, type=Type.string)
        self.add_option("DEPTH", "max recursion depth", required=True, default=3, type=Type.int)
        self.add_option("TIMEOUT", "timeout", required=True, default=5, type=Type.int)
        self.add_option("COOKIES", "cookies", required=False, type=Type.string)
        self.add_option("USER-AGENT", "user agent", required=True, default=DEFAULT_USER_AGENT, type=Type.string)

    def headers(self, headers):
        try:
            response = requests.get(self.url, timeout=self.timeout, allow_redirects=True, headers=headers)
            for header in INTERESTING_HEADERS:
                if header in response.headers:
                    print(f"{header}: {response.headers.get(header)}")
            print()
        except requests.exceptions.RequestException:
            return

    def favicon(self, headers):
        try:
            response = requests.get(urljoin(self.url, "/favicon.ico"), timeout=self.timeout, headers=headers)
            if response.status_code == 200:
                favicon_hash = hashlib.md5(response.content).hexdigest()

                with open("data/favicon-database.json") as f:
                    database = json.load(f)
                    for entry in database:
                        if entry["hash"] == favicon_hash:
                            print(f"favicon: {entry["name"]}")
                            break
                    else:
                        print(f"favicon: {favicon_hash}")
                print()
        except requests.exceptions.RequestException:
            return

    def robots(self, headers):
        try:
            response = requests.get(urljoin(self.url, "/robots.txt"), timeout=self.timeout, headers=headers)
            if response.status_code == 200:
                print("ROBOTS.TXT")
                print(response.text)
                print()
        except requests.exceptions.RequestException:
            return

    def crawl(self, headers):
        directories = set()
        forms = set()
        scripts = set()
        emails = set()
        comments = set()

        def callback(url, soup):
            directories.add(urlparse(url).path)

            html = str(soup)
            for match in re.finditer(EMAIL_REGEX, html):
                emails.add(match.group())
            for match in re.finditer(HTML_COMMENT_REGEX, html):
                comments.add(match.group())

            for form in soup.find_all("form"):
                method, action, args = parse_form(form)
                forms.add(f"{method.upper()}\t{urlparse(urljoin(url, action)).path}\targs:{",".join(args)}")

            for script in soup.find_all("script", src=True):
                scripts.add(urlparse(urljoin(url, script.get("src"))).path)

        asyncio.run(crawler(self.url, self.depth, self.timeout, callback, headers))

        if directories:
            if "" in directories:
                directories.remove("")
            print("=" * 5, "DIRECTORIES", "=" * 5)
            print("\n".join(sorted(directories)))
            print()
        if forms:
            print("=" * 5, "FORMS", "=" * 5)
            print("\n".join(forms))
            print()
        if scripts:
            print("=" * 5, "SCRIPTS", "=" * 5)
            unknown = []
            with open("data/web-technology.json") as f:
                technologies = json.load(f)
                for script in scripts:
                    resp = requests.get(urljoin(self.url, script))
                    hashed = hashlib.md5(resp.content).hexdigest()
                    for entry in technologies:
                        if hashed == entry["hash"]:
                            print(entry["name"])
                            break
                    else:
                        unknown.append(script)
            print("\n".join(unknown))
            print()
        if emails:
            print("=" * 5, "EMAILS", "=" * 5)
            print("\n".join(emails))
            print()
        if comments:
            print("=" * 5, "COMMENTS", "=" * 5)
            print("\n".join(comments))
            print()

    def run(self):
        headers = {"user-Agent": self.user_agent}
        if self.cookies:
            headers["Cookies"] = self.cookies

        self.headers(headers)
        self.favicon(headers)
        self.robots(headers)
        self.crawl(headers)
