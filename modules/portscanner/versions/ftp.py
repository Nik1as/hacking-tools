import asyncio

from modules.portscanner.versions import VersionDetection
from utils.network import Protocol


class FTPVersion(VersionDetection):

    def __init__(self):
        super().__init__("ftp", Protocol.TCP)

    async def run(self, host: str, state):
        reader, writer = await asyncio.open_connection(host, state.port)

        banner = await reader.read(1024)
        state.version = banner.decode().split(" ", 1)[1]

        writer.close()
        await writer.wait_closed()
