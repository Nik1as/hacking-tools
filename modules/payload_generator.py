import payloads
from module import Module, Type


class PayloadGenerator(Module):

    def __init__(self):
        super().__init__("payload_generator",
                         ["payload", "generator", "reverse", "shell"],
                         "generate reverse shell payloads")

        self.add_option("PAYLOAD-NAME", "payload name", required=True, type=Type.string, choices=payloads.names())
        self.add_option("LHOST", "local host", required=True, type=Type.host)
        self.add_option("LPORT", "local port", required=True, default=1337, type=Type.int)
        self.add_option("ENCODE", "encode payload in base64", required=True, default=False, type=Type.bool)

    def run(self):
        print(payloads.get(self.payload_name, self.lhost, self.lport, self.encode))
