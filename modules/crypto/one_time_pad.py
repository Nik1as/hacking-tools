import base64
import binascii
import secrets

from module import Module, Type
from utils.others import xor


class OneTimePad(Module):

    def __init__(self):
        super().__init__("one_time_pad",
                         ["xor", "otp", "one", "time", "pad", "encryption", "decryption", "cipher"],
                         "encrypt and decrypt data with the one time pad")

        self.add_option("DATA", "data to encrypt or decrypt", required=True, type=Type.string)
        self.add_option("KEY", "key used for encryption and decryption (base64 encoded)", required=False, type=Type.string)
        self.add_option("DECRYPT", "decrypt the data", required=True, default=False, type=Type.bool)

    def run(self):
        try:
            if self.decrypt:
                data = base64.b64decode(self.data)
            else:
                data = self.data.encode()

            if self.key is None:
                key = secrets.token_bytes(len(data))
                print("key:", base64.b64encode(key).decode())
            else:
                key = base64.b64decode(self.key)
                if len(key) < len(data):
                    print("[-] the key must be at least as long as the message")
                    return
                key = key[:len(data)]

            result = xor(data, key)
            if self.decrypt:
                print(result.decode())
            else:
                print(base64.b64encode(result).decode())

        except binascii.Error:
            print("[-] the inputs are no valid base64 strings")
