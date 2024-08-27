from abc import ABC, abstractmethod

from utils.network import Protocol


class Script(ABC):

    def __init__(self, service: str, protocol: Protocol):
        self.service = service
        self.protocol = protocol

    @abstractmethod
    async def run(self, host: str, state):
        pass
