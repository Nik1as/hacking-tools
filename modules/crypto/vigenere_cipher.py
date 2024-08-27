from module import Module, Type


class VigenereCipher(Module):

    def __init__(self):
        super().__init__("vigenere_cipher",
                         ["vigenere", "cipher", "shift"],
                         "encrypt and decrypt with the vigenere cipher")

        self.add_option("DATA", "data to encrypt or decrypt", required=True, type=Type.string)
        self.add_option("KEY", "key", required=True, type=Type.string)
        self.add_option("MODE", "encrypt, decrypt or key-recovery", required=True, default="ENCRYPT", type=Type.string,
                        choices=["ENCRYPT", "DECRYPT", "KEY-RECOVERY"])

    def encrypt(self):
        key = self.key.upper()
        plaintext = self.data

        ciphertext = ""
        key_repeated = (key * (len(plaintext) // len(key))) + key[:len(plaintext) % len(key)]
        for i in range(len(plaintext)):
            if plaintext[i].isalpha():
                shift = ord(key_repeated[i].upper()) - ord("A")
                if plaintext[i].isupper():
                    ciphertext += chr((ord(plaintext[i]) + shift - ord("A")) % 26 + ord("A"))
                else:
                    ciphertext += chr((ord(plaintext[i]) + shift - ord("a")) % 26 + ord("a"))
            else:
                ciphertext += plaintext[i]
        print(ciphertext)

    def decrypt(self):
        key = self.key.upper()
        ciphertext = self.data

        plaintext = ""
        key_repeated = (key * (len(ciphertext) // len(key))) + key[:len(ciphertext) % len(key)]
        for i in range(len(ciphertext)):
            if ciphertext[i].isalpha():
                shift = ord(key_repeated[i].upper()) - ord("A")
                if ciphertext[i].isupper():
                    plaintext += chr((ord(ciphertext[i]) - shift - ord("A")) % 26 + ord("A"))
                else:
                    plaintext += chr((ord(ciphertext[i]) - shift - ord("a")) % 26 + ord("a"))
            else:
                plaintext += ciphertext[i]
        print(plaintext)

    def run(self):
        mode = self.mode.casefold()

        if mode == "ENCRYPT":
            self.decrypt()
        elif mode == "DECRYPT":
            self.encrypt()
        elif mode == "KEY-RECOVERY":
            print("not implemented!")
        else:
            print("[-] invalid mode")
