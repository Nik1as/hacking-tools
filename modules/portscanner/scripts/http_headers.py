import requests

from modules.portscanner.scripts import Script
from utils.network import Protocol
from utils.web import get_url


class HTTPHeaders(Script):

    def __init__(self):
        super().__init__("http", Protocol.TCP)

    async def run(self, host: str, state) -> str:
        response = requests.get(get_url(host, state.port))
        results = []
        if "Server" in response.headers:
            results.append(f"|_server: {response.headers['Server']}")
        if "X-Powered-By" in response.headers:
            software = response.headers['X-Powered-By']
            results.append(f"|_software: {software}")
            if "PHP" in software and "8.1.0-dev" in software:
                results.append(f"|_vulnerable PHP version: https://www.exploit-db.com/exploits/49933")
            if "X-Version" in response.headers:
                results.append(f"|_version: {response.headers['X-Version']}")
            if "X-Runtime" in response.headers:
                results.append(f"|_version: {response.headers['X-Runtime']}")
            if "X-AspNet-Version" in response.headers:
                results.append(f"|_version: {response.headers['X-AspNet-Version']}")
        if results:
            state.scripts.append("http-headers:\n" + "\n".join(results))
