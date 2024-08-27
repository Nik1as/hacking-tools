import itertools
import string

from config import MAX_WORDLIST_SIZE
from module import Module, Type


class WordlistCharset(Module):

    def __init__(self):
        super().__init__("wordlist_charset",
                         ["wordlist", "generator", "generate", "charset"],
                         "create wordlists with a charset and length")

        self.add_option("OUTPUT", "path to the output file", required=True, type=Type.path)
        self.add_option("CHARSET", "charset for the password", required=False, type=Type.string)
        self.add_option("MIN-LENGTH", "minimum password length", required=True, default=4, type=Type.int)
        self.add_option("MAX-LENGTH", "maximum password length", required=True, default=8, type=Type.int)
        self.add_option("UPPERCASE", "add uppercase letters to the charset", required=True, default=True, type=Type.bool)
        self.add_option("LOWERCASE", "add lowercase letters to the charset", required=True, default=True, type=Type.bool)
        self.add_option("DIGITS", "add digits to the charset", required=True, default=True, type=Type.bool)
        self.add_option("SPECIAL_CHARS", "add special characters to the charset", required=True, default=True, type=Type.bool)

    def run(self):
        charset = self.charset
        if not charset:
            charset = ""
            if self.uppercase:
                charset += string.ascii_uppercase
            if self.lowercase:
                charset += string.ascii_lowercase
            if self.digits:
                charset += string.digits
            if self.special_chars:
                charset += string.punctuation

            if charset == "":
                print("[-] please specify some characters")
                return

        if self.min_length > self.max_length:
            print("[-] the minimum length must be smaller than the maximum length")
            return

        if sum(len(charset) ** i for i in range(self.min_length, self.max_length + 1)) > MAX_WORDLIST_SIZE:
            print("[-] the number of combinations is to big")
            return

        wordlist = []
        for i in range(self.min_length, self.max_length + 1):
            wordlist.extend(map(lambda x: "".join(x), itertools.combinations_with_replacement(charset, i)))

        with open(self.output, "w") as f:
            f.write("\n".join(wordlist))
            print("[+] wordlist created")
