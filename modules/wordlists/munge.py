import itertools
import os.path
import string

from module import Module, Type
from utils.others import read_wordlist


class Munge(Module):
    LEET_TRANSFORMS = [
        [("e", "3")],
        [("a", "4")],
        [("o", "0")],
        [("i", "!")],
        [("i", "1")],
        [("l", "1")],
        [("a", "@")],
        [("s", "$")],
        [("e", "3"), ("a", "4"), ("o", "0"), ("i", "1"), ("s", "$")],
        [("e", "3"), ("a", "@"), ("o", "0"), ("i", "1"), ("s", "$")],
        [("e", "3"), ("a", "@"), ("o", "0"), ("i", "!"), ("s", "$")],
        [("e", "3"), ("a", "@"), ("o", "0"), ("l", "!"), ("s", "$")],
        [("e", "3"), ("a", "@"), ("o", "0"), ("l", "1"), ("s", "$")],
    ]

    def __init__(self):
        super().__init__("munge",
                         ["munge", "password", "password", "generate", "generator", "wordlist"],
                         "generate a wordlist")

        self.add_option("WORDLIST", "path to a wordlist", required=True, type=Type.path)
        self.add_option("OUTPUT", "path to the output file", required=True, type=Type.path)
        self.add_option("NUMBERS", "add numbers at the beginning and end", required=True, default=True, type=Type.bool)
        self.add_option("YEARS", "add years at the end", required=True, default=True, type=Type.bool)
        self.add_option("LEET", "perform leet transformation", required=True, default=True, type=Type.bool)
        self.add_option("CASE", "perform case transformation", required=True, default=True, type=Type.bool)
        self.add_option("SPECIAL-CHARS", "add special chars at the end", required=True, default=True, type=Type.bool)
        self.add_option("COMBINATIONS", "maximum number of words to combine", required=True, default=2, type=Type.int)

    def munge(self, word: str) -> list[str]:
        result = [word]

        if self.numbers:
            for i in range(11):
                result.append(f"{i}{word}")
                result.append(f"{word}{i}")
                result.append(f"{word}{str(i).zfill(2)}")
        if self.years:
            for year in range(1970, 2030):
                result.append(f"{word}{year}")
        if self.leet:
            for leet in self.LEET_TRANSFORMS:
                tmp = word
                for char, replacement in leet:
                    tmp = tmp.replace(char, replacement)
                result.append(tmp)
        if self.case:
            result.append(word.upper())
            result.append(word.lower())
            result.append(word.capitalize())
            result.append(word.capitalize().swapcase())

            for i in range(len(word)):
                result.append(word[:i] + word[i].upper() + word[i + 1:])
                result.append(word[:i] + word[i].lower() + word[i + 1:])

        if self.special_chars:
            for char in string.punctuation:
                result.append(f"{word}{char}")

        return result

    def run(self):
        if not os.path.isfile(self.wordlist):
            print("[-] wordlist does not exist")
            return

        result = []
        wordlist = set(read_wordlist(self.wordlist))
        for word in wordlist:
            result.extend(self.munge(word))
        for words in itertools.combinations(wordlist, self.combinations):
            result.extend(self.munge("".join(words)))

        with open(self.output, "w") as f:
            f.write("\n".join(result))
            print("[+] wordlist created")
