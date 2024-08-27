import hashlib
import os.path

from module import Module, Type
from utils.others import read_wordlist


class RainbowTable(Module):

    def __init__(self):
        super().__init__("rainbow_table",
                         ["rainbow", "table", "hash"],
                         "create a rainbow table")

        self.add_option("ALGORITHM", "hash algorithm", required=True, type=Type.string, choices=hashlib.algorithms_available)
        self.add_option("WORDLIST", "path to a wordlist of passwords", required=True, type=Type.path)
        self.add_option("OUTPUT", "path to the output file", required=True, type=Type.path)
        self.add_option("SEPARATOR", "char to separate hash and password", default="$", required=True, type=Type.char)

    def run(self):
        if not os.path.isfile(self.wordlist):
            print("[-] wordlist does not exist")
            return

        with open(self.output_file, "w") as out_file:
            for password in read_wordlist(self.wordlist):
                h = hashlib.new(self.algorithm)
                h.update(password.strip().encode())
                out_file.write(f"{h.hexdigest()}{self.separator}{password}")
