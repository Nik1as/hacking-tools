import asyncio
import string

from module import Module, Type
from utils.web import crawler


class CeWl(Module):

    def __init__(self):
        super().__init__("cewl",
                         ["wordlist", "generator", "website", "cewl"],
                         "spider a website an return a list of words")

        self.add_option("URL", "target url", required=True, type=Type.string)
        self.add_option("DEPTH", "depth to spider to", required=True, default=4, type=Type.int)
        self.add_option("OUTPUT", "path to the output file", required=True, type=Type.path)
        self.add_option("TIMEOUT", "timeout", required=True, default=5, type=Type.int)
        self.add_option("MIN-WORD-LENGTH", "minimum word length", required=False, default=3, type=Type.int)
        self.add_option("MAX-WORD-LENGTH", "maximum word length", required=False, type=Type.int)
        self.add_option("LOWERCASE", "save all words in lowercase", required=True, default=False, type=Type.bool)
        self.add_option("REMOVE-DIGITS", "remove the digits in words", required=True, default=False, type=Type.bool)
        self.add_option("REMOVE-SPECIAL-CHARS", "remove the special chars in words", required=True, default=True, type=Type.bool)

    def run(self):
        words = set()

        def callback(url, soup):
            new_words = soup.get_text(separator=" ", strip=True).split(" ")
            new_words = map(lambda x: x.replace("\n", "").strip(), new_words)
            new_words = map(lambda x: x.replace("\t", "").strip(), new_words)

            if self.remove_digits:
                new_words = map(lambda x: x.translate(str.maketrans("", "", string.digits)), new_words)
            if self.remove_special_chars:
                new_words = map(lambda x: x.translate(str.maketrans("", "", string.punctuation)), new_words)
            if self.min_word_length is not None:
                new_words = filter(lambda x: self.min_word_length <= len(x), new_words)
            if self.max_word_length is not None:
                new_words = filter(lambda x: len(x) <= self.max_word_length, new_words)
            if self.lowercase:
                new_words = map(lambda x: x.lower(), new_words)

            new_words = filter(lambda x: bool(x), new_words)
            words.update(new_words)

        asyncio.run(crawler(self.url, self.depth, self.timeout, callback))

        with open(self.output, "w") as f:
            f.write("\n".join(words))
            print(f"[+] wordlist created with {len(words)} words")
