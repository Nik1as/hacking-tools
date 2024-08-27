import requests

import payloads
from module import Module, Type

PAYLOADS = [
    "${7*7}",
    "${{7*7}}",
    "{{7*7}}",
    "{7*7}",
    "{% 7*7 %}",
    "{# 7*7 #}",
    "@(7*7)",
    "<%= 7*7 %>"
]


class ServerSideTemplateInjection(Module):

    def __init__(self):
        super().__init__("server_side_template_injection",
                         ["server", "side", "template", "injection", "web", "ssti"],
                         "find and exploit local file inclusions",
                         payload=payloads.default())

        self.add_option("URL", "url", required=True, type=Type.string)

    def run(self):
        for payload, rev_shell_payload in PAYLOADS:
            resp = requests.get(self.url + payload)
            if "49" in resp.text:
                print("ssti found:", payload)
                break
