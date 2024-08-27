import asyncssh

from modules.portscanner.services import ServiceDetection
from utils.network import Protocol


class SSHDetect(ServiceDetection):

    def __init__(self):
        super().__init__([22], Protocol.TCP)

    async def run(self, host, state):
        try:
            async with asyncssh.connect(host=host,
                                        port=state.port,
                                        known_hosts=None):
                state.service = "ssh"
        except asyncssh.misc.PermissionDenied:
            state.service = "ssh"
        except:
            pass
