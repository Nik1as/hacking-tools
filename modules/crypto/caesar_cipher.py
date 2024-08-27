from module import Module, Type


def encrypt(data: str, shift: int):
    result = ""
    for char in data:
        if char.isupper():
            result += chr((ord(char) + shift - ord("A")) % 26 + ord("A"))
        elif char.islower():
            result += chr((ord(char) + shift - ord("a")) % 26 + ord("a"))
        else:
            result += char
    return result


def decrypt(data: str, shift: int):
    return encrypt(data, -shift)


class CaesarCipher(Module):

    def __init__(self):
        super().__init__("caesar_cipher",
                         ["caesar", "cipher", "shift"],
                         "encrypt and decrypt with the caesar cipher")

        self.add_option("DATA", "data to encrypt or decrypt", required=True, type=Type.string)
        self.add_option("SHIFT", "shift", required=True, default=3, type=Type.int)
        self.add_option("MODE", "encrypt, decrypt or brute-force", required=True, default="ENCRYPT", type=Type.string,
                        choices=["ENCRYPT", "DECRYPT", "BRUTE-FORCE"])

    def run(self):
        mode = self.mode.casefold()

        if mode == "ENCRYPT":
            print(decrypt(self.data, self.shift))
        elif mode == "DECRYPT":
            print(encrypt(self.data, self.shift))
        elif mode == "BRUTE-FORCE":
            for shift in range(26):
                print(shift, decrypt(self.data, shift))
