import re

from module import Module, Type

HASH_PATTERNS = [
    (re.compile(r"^[a-f0-9]{4}$", re.IGNORECASE),
     [("CRC-16", None)]),
    (re.compile(r"^[a-f0-9]{6}$", re.IGNORECASE),
     [("CRC-24", None)]),
    (re.compile(r"^(\$crc32\$)?([a-f0-9]{8}.)?[a-f0-9]{8}$", re.IGNORECASE),
     [("CRC-32", None)]),

    (re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE),
     [("MD5", 0),
      ("MD4", 900),
      ("md5(utf16le($pass))", 70),
      ("md5(md5($pass))", 2600),
      ("md5(md5(md5($pass)))", 3500)]),
    (re.compile(r"^[a-f0-9]{32}:[a-z0-9]+$", re.IGNORECASE),
     [("md5($pass.$salt)", 10),
      ("md5($salt.$pass)", 20),
      ("md5(utf16le($pass).$salt)", 30),
      ("md5($salt.utf16le($pass))", 40),
      ("HMAC-MD5 (key = $pass)", 50),
      ("HMAC-MD5 (key = $salt)", 60),
      ("md5($salt.md5($pass))", 3710)]),
    (re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE),
     [("SHA1", 100),
      ("sha1(utf16le($pass))", 170),
      ("MySQL4.1/MySQL5", 300)]),
    (re.compile(r"^[a-f0-9]{40}:[a-z0-9]+$", re.IGNORECASE),
     [("sha1($pass.$salt)", 110),
      ("sha1($salt.$pass)", 120),
      ("sha1(utf16le($pass).$salt)", 130),
      ("sha1($salt.utf16le($pass))", 140),
      ("HMAC-SHA1 (key = $pass)", 150),
      ("HMAC-SHA1 (key = $salt)", 160)]),
    (re.compile(r"^[a-f0-9]{56}$", re.IGNORECASE),
     [("SHA2-224", 1300),
      ("SHA3-224", 17300),
      ("Keccak-224 ", 17700)]),
    (re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE),
     [("SHA2-256", 1400),
      ("sha256(utf16le($pass))", 1470),
      ("SHA3-256", 17400),
      ("Keccak-256", 17800)],),
    (re.compile(r"^[a-f0-9]{64}:[a-z0-9]+$", re.IGNORECASE),
     [("sha256($pass.$salt)", 1410),
      ("sha256($salt.$pass)", 1420),
      ("sha256(utf16le($pass).$salt)", 1430),
      ("sha256($salt.utf16le($pass))", 1440),
      ("HMAC-SHA256 (key = $pass)", 1450),
      ("HMAC-SHA256 (key = $salt)", 1460)]),
    (re.compile(r"^[a-z0-9]{96}$", re.IGNORECASE),
     [("SHA2-384", 10800),
      ("sha384(utf16le($pass))", 10870),
      ("SHA3-384", 17500),
      ("Keccak-384", 17900)],),
    (re.compile(r"^[a-f0-9]{96}:[a-z0-9]+$", re.IGNORECASE),
     [("sha384($pass.$salt)", 10810),
      ("sha384($salt.$pass)", 10820),
      ("sha384(utf16le($pass).$salt)", 10830),
      ("sha384($salt.utf16le($pass))", 10840)]),
    (re.compile(r"^[a-f0-9]{128}$", re.IGNORECASE),
     [("SHA2-512", 1700),
      ("sha512(utf16le($pass))", 1770),
      ("SHA3-512", 17600),
      ("Keccak-512", 18000)],),
    (re.compile(r"^[a-f0-9]{128}:[a-z0-9]+$", re.IGNORECASE),
     [("sha512($pass.$salt)", 1710),
      ("sha512($salt.$pass)", 1720),
      ("sha512(utf16le($pass).$salt)", 1730),
      ("sha512($salt.utf16le($pass))", 1740),
      ("HMAC-SHA512 (key = $pass)", 1750),
      ("HMAC-SHA512 (key = $salt)", 1760)]),
    (re.compile(r"^\$P\$[a-z0-9\/.]{31}$", re.IGNORECASE),
     [("phpass, WordPress (MD5), Joomla (MD5)", 400)]),
    (re.compile(r"^\$BLAKE2\$[a-f0-9]{128}$", re.IGNORECASE),
     [("BLAKE2b-512", 600)]),
    (re.compile(r"^\$BLAKE2\$[a-f0-9]{128}:[a-z0-9]+$", re.IGNORECASE),
     [("BLAKE2b-512($pass.$salt)", 610),
      ("BLAKE2b-512($salt.$pass)", 620)]),
    (re.compile(r"^[a-f0-9]{40}(:.+)?$", re.IGNORECASE),
     [("RIPEMD-160", 6000)]),
    (re.compile(r"^\$2[ayb]\$.{56}$", re.IGNORECASE),
     [("bcrypt $2*$, Blowfish (Unix)", 3200)]),
    (re.compile(r"^[a-z0-9\/.]{12}[.26AEIMQUYcgkosw]$", re.IGNORECASE),
     [("descrypt, DES (Unix), Traditional DES", 1500)]),
    (re.compile(r"^[a-f0-9]{16}$", re.IGNORECASE),
     [("Half MD5", 5100),
      ("MySQL323 ", 200)]),
    (re.compile(r"^(\$NT\$)?[a-f0-9]{32}$", re.IGNORECASE),
     [("NTLM", 1000)]),
    (re.compile(r"^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/.]+$", re.IGNORECASE),
     [("Python passlib pbkdf2-sha512", 20200)]),
    (re.compile(r"^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/.]+$", re.IGNORECASE),
     [("Python passlib pbkdf2-sha256", 20300)]),
    (re.compile(r"^\$pbkdf2$[0-9]+\$[a-z0-9]+\$[a-z0-9\/.]+$", re.IGNORECASE),
     [("Python passlib pbkdf2-sha1", 20400)]),
    (re.compile(r"^md5\$[a-f0-9]+\$[a-z0-9]{32}$", re.IGNORECASE),
     [("Python Werkzeug MD5 (HMAC-MD5 (key = $salt))", 30000)]),
    (re.compile(r"^sha256\$[a-f0-9]+\$[a-z0-9]{24}$", re.IGNORECASE),
     [("Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt))", 30120)]),

    (re.compile(r"^[a-f0-9]{32}:[a-z0-9]{32}$", re.IGNORECASE),
     [("Joomla < 2.5.18", 11)]),
    (re.compile(r"^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$", re.IGNORECASE),
     [("sha256crypt $5$, SHA256 (Unix)", 7400)]),
]


class HashIdentifier(Module):

    def __init__(self):
        super().__init__("hash_identifier",
                         ["hash", "identifier", "algorithm"],
                         "identify the algorithm used for a hash")

        self.add_option("HASH", "hash value", required=True, type=Type.string)

    def run(self):
        for pattern, matches in HASH_PATTERNS:
            if pattern.match(self.hash):
                for algorithm, mode in matches:
                    if mode is None:
                        print(algorithm)
                    else:
                        print(algorithm, mode)
