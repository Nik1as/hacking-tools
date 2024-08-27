import requests

from modules.portscanner.scripts import Script
from utils.network import Protocol
from utils.web import get_url


class HTTPRobots(Script):

    def __init__(self):
        super().__init__("http", Protocol.TCP)

    async def run(self, host: str, state):
        try:
            response = requests.get(get_url(host, state.port, "/robots.txt"))
            if response.status_code == 200:
                state.scripts.append(f"/robots.txt\n\t{response.text}")
        except requests.exceptions.ConnectionError:
            pass
