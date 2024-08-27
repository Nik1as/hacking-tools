import aiohttp

from modules.portscanner.versions import VersionDetection
from utils.network import Protocol


class HTTPVersion(VersionDetection):

    def __init__(self):
        super().__init__("http", Protocol.TCP)

    async def run(self, host: str, state):
        async with aiohttp.client.ClientSession() as client:
            async with client.get(f"http://{host}:{state.port}") as response:
                state.version = response.headers.get("Server", "")
