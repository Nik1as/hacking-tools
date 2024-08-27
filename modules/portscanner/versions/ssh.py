import asyncio

from modules.portscanner.versions import VersionDetection
from utils.network import Protocol


class SSHVersion(VersionDetection):

    def __init__(self):
        super().__init__("ssh", Protocol.TCP)

    async def run(self, host: str, state):
        reader, writer = await asyncio.open_connection(host, state.port)

        writer.write(b"SSH-2.0-OpenSSH_7.3\r\n")
        await writer.drain()

        banner = await reader.read(1024)
        state.version = banner.decode()

        writer.close()
        await writer.wait_closed()
