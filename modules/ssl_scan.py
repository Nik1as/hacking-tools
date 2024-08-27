import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from module import Module, Type

VERSIONS = [
    (ssl.PROTOCOL_TLSv1, "tls 1.0"),
    (ssl.PROTOCOL_TLSv1_1, "tls 1.1"),
    (ssl.PROTOCOL_TLSv1_2, "tls 1.2"),
    (ssl.PROTOCOL_TLS, "tls 1.3")
]


class SSLScan(Module):

    def __init__(self):
        super().__init__("ssl_scan",
                         ["ssl", "tls", "scan"],
                         "ssl scan")

        self.add_option("RHOST", "target host", required=True, type=Type.host)
        self.add_option("RPORT", "target port", required=True, default=443, type=Type.int)
        self.add_option("TIMEOUT", "timeout", required=True, default=3, type=Type.float)

    def run(self):
        cert = None

        print("SSL/TLS Versions")
        for version, name in VERSIONS:
            try:
                cert = ssl.get_server_certificate((self.rhost, self.rport), ssl_version=version, timeout=self.timeout)
                cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
                print(name)
            except ssl.SSLError:
                pass

        if cert is not None:
            print()
            print("subject:", cert.subject.rfc4514_string())
            print("issuer:", cert.issuer.rfc4514_string())
            print("valid from:", cert.not_valid_before_utc)
            print("valid to:", cert.not_valid_after_utc)
