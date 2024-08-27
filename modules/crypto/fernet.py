import cryptography.fernet

from module import Module, Type


class Fernet(Module):

    def __init__(self):
        super().__init__("fernet",
                         ["fernet", "encryption", "decryption"],
                         "encrypt and decrypt with the fernet algorithm")

        self.add_option("DATA", "data to encrypt or decrypt", required=True, type=Type.string)
        self.add_option("KEY", "key used for encryption and decryption", required=False, type=Type.string)
        self.add_option("DECRYPT", "decrypt the data", required=True, default=False, type=Type.bool)

    def run(self):
        if self.key is None:
            key = cryptography.fernet.Fernet.generate_key()
            print("key:", key.decode())
        else:
            key = self.key.encode()

        cipher = cryptography.fernet.Fernet(key)

        if self.decrypt:
            print(cipher.decrypt(self.data.encode()).decode())
        else:
            print(cipher.encrypt(self.data.encode()).decode())
