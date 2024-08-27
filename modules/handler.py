import socket

from module import Module, Type


class Handler(Module):

    def __init__(self):
        super().__init__("handler",
                         ["handler", "shell", "remote", "code", "execution", "listener"],
                         "listen for a remote shell")

        self.add_option("LHOST", "target host", required=True, type=Type.host)
        self.add_option("LPORT", "target port", required=True, default=5555, type=Type.int)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.lhost, self.lport))
            s.listen(1)
            print(f"[+] listen on {self.lhost}:{self.lport}")
            conn, addr = s.accept()
            print(f"[+] connection received from {addr[0]}:{addr[1]}")
            return conn, addr
