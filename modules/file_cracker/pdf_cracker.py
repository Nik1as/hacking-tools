import os.path

from pypdf import PdfReader, PasswordType

from module import Module, Type
from utils.others import read_wordlist


class PDFCracker(Module):

    def __init__(self):
        super().__init__("pdf_cracker",
                         ["pdf", "cracker", "crack"],
                         "bruteforce password protected pdf files")

        self.add_option("PDF-FILE", "path to a pdf file", required=True, type=Type.path)
        self.add_option("WORDLIST", "path to a wordlist of passwords", required=True, type=Type.path)

    def run(self):
        if not os.path.isfile(self.pdf_file):
            print("[-] pdf file does not exist")
            return
        if not os.path.isfile(self.wordlist):
            print("[-] wordlist does not exist")
            return

        reader = PdfReader(self.pdf_file)
        for password in read_wordlist(self.wordlist):
            if reader.decrypt(password) == PasswordType.OWNER_PASSWORD:
                print(f"[+] password found: {password}")
                return
        else:
            print("[-] password is not in the wordlist")
