import os.path
import zipfile

from module import Module, Type
from utils.others import read_wordlist


class ZipCracker(Module):

    def __init__(self):
        super().__init__("zip_cracker",
                         ["zip", "cracker", "crack"],
                         "bruteforce password protected zip files")

        self.add_option("ZIP-FILE", "path to a zip file", required=True, type=Type.path)
        self.add_option("WORDLIST", "path to a wordlist of passwords", required=True, type=Type.path)

    def check_zip(self, password: str):
        try:
            with zipfile.ZipFile(self.zip_file) as file:
                file.extractall(pwd=password.encode())
                return True
        except RuntimeError:
            return False

    def run(self):
        if not os.path.isfile(self.zip_file):
            print("[-] pdf file does not exist")
            return
        if not os.path.isfile(self.wordlist):
            print("[-] wordlist does not exist")
            return

        for password in read_wordlist(self.wordlist):
            if self.check_zip(password):
                print(f"[+] password found: {password}")
                return
        else:
            print("[-] password is not in the wordlist")
