import http.server
import os

from module import Module, Type


class HttpServer(Module):

    def __init__(self):
        super().__init__("http_server",
                         ["http", "server", "web"],
                         "setup a simple http server")

        self.add_option("DIRECTORY", "directory", required=True, default="./", type=Type.string)
        self.add_option("LHOST", "local host", required=True, default="localhost", type=Type.string)
        self.add_option("LPORT", "local port", required=True, default=8080, type=Type.int)

    def run(self):
        cwd = os.getcwd()

        try:
            os.chdir(self.directory)

            server = http.server.HTTPServer((self.lhost, self.lport), http.server.SimpleHTTPRequestHandler)
            print(f"[+] server started at http://{self.lhost}:{self.lport} in directory {os.getcwd()}")

            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass

            server.server_close()
        except FileNotFoundError:
            print("[-] directory does not exist")

        os.chdir(cwd)
