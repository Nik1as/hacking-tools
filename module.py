import re
import socket
import time
from abc import ABC, abstractmethod

from scapy.arch import get_if_addr
from scapy.interfaces import get_if_list

import payloads
import sessions
from utils.others import print_table


class Type:

    @staticmethod
    def string(value: str) -> str:
        return value.strip()

    @staticmethod
    def char(value: str) -> str:
        if len(value.strip()) != 1:
            raise ValueError("invalid value")
        return value.strip()

    @staticmethod
    def int(value: str) -> int:
        if re.match("^([0-9]+)$", value):
            return int(value)
        raise ValueError("invalid value")

    @staticmethod
    def float(value: str) -> float:
        if re.match("^([0-9]+(.[0-9]*)?)$", value):
            return float(value)
        raise ValueError("invalid value")

    @staticmethod
    def bool(value: str) -> bool:
        if value.casefold() in ("true", "1", "y", "yes"):
            return True
        elif value.casefold() in ("false", "0", "n", "no"):
            return False
        raise ValueError("invalid value")

    @staticmethod
    def int_list(value: str) -> list[int]:
        if re.match("^([0-9]+(,[0-9]+)*)$", value):
            return list(map(int, value.split(",")))
        raise ValueError("invalid value")

    @staticmethod
    def string_list(value: str) -> list[str]:
        if re.match("^([a-zA-z]+(,[a-zA-Z]+)*)$", value):
            return value.split(",")
        raise ValueError("invalid value")

    @staticmethod
    def int_list_or_range(value: str) -> list[int]:
        if re.match("^([0-9]+-[0-9]+)$", value):
            start, end = map(int, value.split("-"))
            return list(range(start, end + 1))
        elif re.match("^([0-9]+(,[0-9]+)*)$", value):
            return list(map(int, value.split(",")))
        raise ValueError("invalid value")

    @staticmethod
    def host(value: str) -> str:
        if value in get_if_list():
            return get_if_addr(value)
        return value

    @staticmethod
    def interface(value: str) -> str:
        if value in get_if_list():
            return value
        raise ValueError("invalid value")

    @staticmethod
    def mac(value: str) -> str:
        if not re.match("^(?:[0-9a-fA-F]:?){12}$", value):
            raise ValueError("invalid value")
        return value

    @staticmethod
    def path(value: str) -> str:
        return value.strip()


class Option:

    def __init__(self, name: str, description: str, required: bool, default, type: callable, choices: list | None):
        self.name = name
        self.description = description
        self.required = required
        self.value = default
        self.type = type
        self.choices = choices

    def set(self, value):
        parsed = self.type(value)
        if self.choices is not None and parsed not in self.choices:
            raise ValueError("value is not in choices")
        self.value = parsed

    def is_assigned(self):
        return self.value is not None

    def normalize_name(self):
        return self.name.lower().replace("-", "_")


class Module(ABC):

    def __init__(self, name: str, tags: list[str], description: str, references: list = None, payload: str = None):
        self.name = name
        self.tags = tags
        self.description = description
        self.references = references
        self.payload = payload
        self.options = []
        self.payload_options = [Option("LHOST", "local host", required=True, default=None, type=Type.host, choices=None),
                                Option("LPORT", "local port", required=True, default=4444, type=Type.int, choices=None),
                                Option("ENCODE", "encode payload in base64", required=True, default=False, type=Type.bool, choices=None)]

    def add_option(self, name, description="", required=True, default=None, type=Type.string, choices=None):
        self.options.append(Option(name, description, required, default, type, choices))

    def set_option(self, name: str, value: str):
        name = name.casefold()

        if name == "payload":
            if self.payload is None:
                raise ValueError("module has no payload")
            if payloads.has(value):
                self.payload = value
                print(f"{name} => {value}")
                return
            else:
                raise ValueError("payload does not exist")

        for option in self.get_options():
            if option.name.casefold() == name.casefold():
                option.set(value)
                if isinstance(option.value, list):
                    value = ",".join(map(str, option.value))
                    if len(value) >= 20:
                        value = value[:20] + "..."
                    print(f"{name} => {value}")
                else:
                    print(f"{name} => {option.value}")
                return
        raise ValueError("invalid option")

    def unset_option(self, name: str):
        for option in self.options:
            if option.name.casefold() == name.casefold():
                option.value = None
                return
        raise ValueError("invalid option")

    def get_options(self):
        yield from self.options
        if self.payload is not None:
            yield from self.payload_options

    def get_payload(self):
        if self.payload is not None:
            return payloads.get(self.payload, self.lhost, self.lport, self.encode)
        raise ValueError("module has no payload")

    def print_options(self):
        if self.options:
            table = []
            for option in self.options:
                value = option.value if option.value is not None else ""
                if isinstance(value, list):
                    value = ",".join(map(str, value))
                    if len(value) > 20:
                        value = value[:20] + "..."

                table.append([option.name,
                              value,
                              option.required,
                              option.description])
            print(f"Module options ({self.name}):")
            print_table(table, headers=["NAME", "VALUE", "REQUIRED", "DESCRIPTION"])

        if self.payload is not None:
            table = []
            for option in self.payload_options:
                value = option.value if option.value is not None else ""
                table.append([option.name,
                              value,
                              option.required,
                              option.description])
            print()
            print(f"Payload options ({self.payload}):")
            print_table(table, headers=["NAME", "VALUE", "REQUIRED", "DESCRIPTION"])

    def print_info(self):
        print("name:", self.name)
        print("tags:", ",".join(self.tags))
        print("description:", self.description)

        if self.options:
            print()

        self.print_options()

        if self.references is not None:
            print()
            print("references:")
            print("\n".join(self.references))

    @abstractmethod
    def run(self) -> tuple[socket.socket, tuple[str, int]] | None:
        pass


class RemoteCodeExecutionModule(Module, ABC):

    def __init__(self, name: str, tags: list, description: str, references: list = None):
        super().__init__(name, tags, description, references, payload=payloads.default())

    @abstractmethod
    def exploit(self):
        pass

    def run(self):
        listener = sessions.Listener(self.lhost, self.lport)
        listener.start()

        time.sleep(3)

        self.exploit()

        time.sleep(3)

        listener.stop()
        listener.join()

        if listener.connected():
            return listener.get()
        else:
            print("[-] exploit completed but no session created!")
