import asyncio
from abc import ABC, abstractmethod

from utils.network import Protocol


class VersionDetection(ABC):

    def __init__(self, service: str, protocol: Protocol):
        self.service = service
        self.protocol = protocol

    @abstractmethod
    async def run(self, host: str, state):
        reader, writer = await asyncio.open_connection(host, state.port)

        banner = await reader.read(1024)
        state.service = banner.decode()

        writer.close()
        await writer.wait_closed()
