import hashlib
import itertools
import math
import multiprocessing
import os

from module import Module, Type
from utils.others import read_wordlist


def hash_cracker(arg):
    passwords, hash, hash_type = arg
    for password in passwords:
        current_hash = hashlib.new(hash_type)
        current_hash.update(password.encode())
        if current_hash.hexdigest() == hash:
            return password


class HashCracker(Module):

    def __init__(self):
        super().__init__("hash_cracker",
                         ["hash", "cracker", "cryptography"],
                         "crack hashes")

        self.add_option("WORDLIST", "path to a wordlist of passwords", required=True, type=Type.path)
        self.add_option("HASH-TYPE", "hash type", required=True, type=Type.string, choices=hashlib.algorithms_available)
        self.add_option("HASH", "hash", required=True, type=Type.string)
        self.add_option("PROCESSES", "number of processes", required=True, default=os.cpu_count(), type=Type.int)

    def run(self):
        if not os.path.isfile(self.wordlist):
            print("[-] wordlist does not exist")
            return

        passwords = list(read_wordlist(self.wordlist))

        if self.processes > 1:
            batch_size = math.ceil(len(passwords) / self.processes)
            batches = [(batch, self.hash, self.hash_type) for batch in itertools.batched(passwords, batch_size)]

            with multiprocessing.Pool(processes=self.processes) as pool:
                for res in pool.imap_unordered(hash_cracker, batches):
                    if res is not None:
                        print("[+] password found:", res)
                        pool.terminate()
                        pool.join()
                        return
        else:
            if password := hash_cracker((passwords, self.hash, self.hash_type)):
                print("[+] password found:", password)
