import asyncio
import concurrent.futures
import os.path
from abc import ABC, abstractmethod

import aiohttp

from config import DEFAULT_USER_AGENT
from module import Module, Type
from utils.others import read_wordlist
from utils.web import get_url


class BruteForceLogin(Module, ABC):

    def __init__(self, name: str, tags: list[str], description: str, references: list[str] = None, port: int = None):
        super().__init__(name, tags, description, references)

        self.add_option("RHOST", "target host", required=True, type=Type.host)
        self.add_option("RPORT", "target port", required=True, default=port, type=Type.int)
        self.add_option("USERNAME", "username", required=False, type=Type.string)
        self.add_option("USERNAMES", "path to a wordlist of usernames", required=False, type=Type.path)
        self.add_option("PASSWORD", "password", required=False, type=Type.string)
        self.add_option("PASSWORDS", "path to a wordlist of passwords", required=False, type=Type.path)
        self.add_option("STOP_ON_SUCCESS", "stop when a valid password is found", required=True, default=True, type=Type.bool)
        self.add_option("TIMEOUT", "timeout", required=True, default=60, type=Type.float)
        self.add_option("VERBOSE", "verbose", required=True, default=True, type=Type.bool)

    def get_usernames(self):
        if self.username is not None:
            return [self.username]
        elif self.usernames is not None:
            if os.path.isfile(self.usernames):
                return list(read_wordlist(self.usernames))
            else:
                print("[-] usernames file does not exist")
        else:
            print("[-] no usernames specified")

    def get_passwords(self):
        if self.password is not None:
            return [self.password]
        elif self.passwords is not None:
            if os.path.isfile(self.passwords):
                return list(read_wordlist(self.passwords))
            else:
                print("[-] usernames file does not exist")
        else:
            print("[-] no usernames specified")


class ThreadedBruteForceLogin(BruteForceLogin, ABC):

    def __init__(self, name: str, tags: list[str], description: str, references: list[str] = None, port: int = None):
        super().__init__(name, tags, description, references, port)

        self.add_option("THREADS", "threads", required=True, default=os.cpu_count(), type=Type.int)

    @abstractmethod
    def login(self, username: str, password: str):
        pass

    def run(self):
        super().run()
        usernames = self.get_usernames()
        if usernames is None:
            return
        passwords = self.get_passwords()
        if passwords is None:
            return

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for username in usernames:
                for password in passwords:
                    futures.append(executor.submit(self.login, username, password))

            for future in concurrent.futures.as_completed(futures):
                if future.result():
                    if self.stop_on_success:
                        executor.shutdown()
                        return


class StopError(Exception):

    def __init__(self):
        super().__init__()


class HTTPBruteForceLogin(BruteForceLogin, ABC):

    def __init__(self, name: str, tags: list[str], description: str, references: list[str] = None):
        super().__init__(name, tags, description, references, 80)

        self.add_option("TARGETURI", "target uri", required=True, default="/", type=Type.string)
        self.add_option("USER-AGENT", "user agent", required=True, default=DEFAULT_USER_AGENT, type=Type.string)

    @abstractmethod
    async def login(self, session: aiohttp.ClientSession, username: str, password: str):
        pass

    async def perform_logins(self):
        usernames = self.get_usernames()
        if usernames is None:
            return
        passwords = self.get_passwords()
        if passwords is None:
            return

        async with aiohttp.ClientSession(get_url(self.rhost, self.rport, self.targeturi),
                                         headers={"User-Agent": self.user_agent},
                                         timeout=aiohttp.ClientTimeout(self.timeout)) as session:
            tasks = [asyncio.create_task(self.login(session, username, password))
                     for username in usernames
                     for password in passwords]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
            for task in pending:
                task.cancel()

    def run(self):
        asyncio.run(self.perform_logins())


class AsyncBruteForceLogin(BruteForceLogin, ABC):

    def __init__(self, name: str, tags: list[str], description: str, references: list[str] = None, port: int = None):
        super().__init__(name, tags, description, references, port)

    @abstractmethod
    async def login(self, username: str, password: str):
        pass

    async def perform_logins(self):
        usernames = self.get_usernames()
        if usernames is None:
            return
        passwords = self.get_passwords()
        if passwords is None:
            return

        tasks = [asyncio.create_task(self.login(username, password))
                 for username in usernames
                 for password in passwords]
        print("start")
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
        for task in pending:
            task.cancel()

    def run(self):
        asyncio.run(self.perform_logins())
