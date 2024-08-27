import ftplib

from modules.portscanner.scripts import Script
from utils.network import Protocol


class FTPAnonymousLogin(Script):

    def __init__(self):
        super().__init__("ftp", Protocol.TCP)

    async def run(self, host: str, state):
        server = ftplib.FTP()
        try:
            server.connect(host, state.port)
            server.login()
            state.scripts.append(f"anonymous login allowed\n{server.dir()}")
        except ftplib.error_perm:
            pass
