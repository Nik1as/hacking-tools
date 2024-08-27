import itertools
import math
import string

from config import MAX_WORDLIST_SIZE
from module import Module, Type


class WordlistPattern(Module):

    def __init__(self):
        super().__init__("wordlist_pattern",
                         ["wordlist", "generator", "generate", "pattern"],
                         "create wordlists with a pattern")

        self.add_option("OUTPUT", "path to the output file", required=True, type=Type.path)
        self.add_option("PATTERN", "password pattern", required=False, type=Type.string)
        self.add_option("UPPERCASE_CHAR", "char that gets replaced by uppercase chars", required=True, default=",", type=Type.char)
        self.add_option("LOWERCASE_CHAR", "char that gets replaced by lowercase chars", required=True, default="@", type=Type.char)
        self.add_option("LETTER_CHAR", "char that gets replaced by letter chars", required=True, default=":", type=Type.char)
        self.add_option("DIGITS_CHAR", "char that gets replaced by digits chars", required=True, default="%", type=Type.char)
        self.add_option("SPECIAL_CHARACTERS_CHAR", "char that gets by lowercase chars", required=True, default="^", type=Type.char)

    def run(self):
        pools = []
        for char in self.pattern:
            match char:
                case self.lowercase_char:
                    pools.append(string.ascii_lowercase)
                case self.uppercase_char:
                    pools.append(string.ascii_uppercase)
                case self.letter_char:
                    pools.append(string.ascii_letters)
                case self.digits_char:
                    pools.append(string.digits)
                case self.special_characters_char:
                    pools.append(string.punctuation)
                case _:
                    pools.append(char)

        if math.prod(map(len, pools)) > MAX_WORDLIST_SIZE:
            print("[-] the number of combinations is to big")
            return

        wordlist = list(map(lambda x: "".join(x), itertools.product(*pools)))

        with open(self.output, "w") as f:
            f.write("\n".join(wordlist))
            print("[+] wordlist created")
