import platform

from module import Module


class Host(Module):

    def __init__(self):
        super().__init__("host",
                         ["host", "kernel", "os", "local", "distribution"],
                         "print information about your local host")

    def run(self):
        uname = platform.uname()

        print("os:", uname.system)
        print("kernel:", uname.release)
        print("distribution:", uname.node)
        print("arch:", uname.machine)
        print("libc:", " ".join(platform.libc_ver()))
        print("python version:", platform.python_version())
        print("hostname:", platform.node())
        print("cpu:", platform.processor())
