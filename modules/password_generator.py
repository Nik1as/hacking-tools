import secrets
import string

from module import Module, Type


class PasswordGenerator(Module):

    def __init__(self):
        super().__init__("password_generator",
                         ["password", "passwords", "generator", "generate", "gen", "random"],
                         "generate secure random passwords")

        self.add_option("CHARSET", "charset", required=False, type=Type.string)
        self.add_option("LENGTH", "length", required=True, default=18, type=Type.int)
        self.add_option("LOWERCASE", "add lowercase letters to the charset", required=True, default=True, type=Type.bool)
        self.add_option("UPPERCASE", "add uppercase letters to the charset", required=True, default=True, type=Type.bool)
        self.add_option("DIGITS", "add digits to the charset", required=True, default=True, type=Type.bool)
        self.add_option("SPECIAL-CHARS", "add special chars to the charset", required=True, default=True, type=Type.bool)

    def run(self):
        if self.charset is not None:
            chars = self.charset
        else:
            chars = ""

            if self.lowercase:
                chars += string.ascii_lowercase
            if self.uppercase:
                chars += string.ascii_uppercase
            if self.digits:
                chars += string.digits
            if self.special_chars:
                chars += string.punctuation

        chars = "".join(set(chars))

        if len(chars) == 0:
            print("[-] no characters specified")
            return

        print("".join(secrets.choice(chars) for _ in range(self.length)))
