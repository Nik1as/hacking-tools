import aiohttp

from modules.portscanner.services import ServiceDetection
from utils.network import Protocol


class HTTPDetect(ServiceDetection):

    def __init__(self):
        super().__init__([80, 8080], Protocol.TCP)

    async def run(self, host: str, state):
        try:
            async with aiohttp.client.ClientSession(timeout=aiohttp.ClientTimeout(20)) as session:
                async with session.get(f"http://{host}:{state.port}"):
                    state.service = "http"
        except aiohttp.ClientResponseError:
            pass
