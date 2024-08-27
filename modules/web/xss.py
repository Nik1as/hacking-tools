import requests

from config import DEFAULT_USER_AGENT
from module import Module, Type
from utils.others import read_wordlist
from utils.web import url_parameters, change_url_param_value

PAYLOADS = list(read_wordlist("data/payloads/xss.txt"))


class XSS(Module):

    def __init__(self):
        super().__init__("xss",
                         ["xss", "scanner", "cross", "site", "scripting", "javascript", "js", "reflected"],
                         "scan for xss vulnerabilities")

        self.add_option("URL", "url", required=True, type=Type.string)
        self.add_option("COOKIES", "cookies", required=False, type=Type.string)
        self.add_option("USER-AGENT", "user agent", required=True, default=DEFAULT_USER_AGENT, type=Type.string)

    def run(self):
        headers = {"User-Agent": self.user_agent}
        if self.cookies:
            headers["Cookies"] = self.cookies

        for param in url_parameters(self.url):
            for payload in PAYLOADS:
                url = change_url_param_value(self.url, param, payload)
                response = requests.get(url, headers=headers)
                if payload in response.text:
                    print("XSS:", payload)
                    break
