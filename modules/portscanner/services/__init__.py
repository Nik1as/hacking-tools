from abc import ABC, abstractmethod

from utils.network import Protocol


class ServiceDetection(ABC):

    def __init__(self, ports: list[int], protocol: Protocol):
        self.ports = ports
        self.protocol = protocol

    @abstractmethod
    async def run(self, host: str, state) -> bool:
        pass
