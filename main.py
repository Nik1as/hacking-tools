import cmd
import glob
import logging
import os
import re
import readline

import scapy.config
from scapy.interfaces import get_if_list

import module
import modules
import payloads
import sessions
import utils.others
from module import Type

scapy.config.conf.verb = False
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

readline.set_completer_delims(" \t\n" + os.sep)

utils.others.import_submodules(modules, recursive=True)

BANNER = r"""
    .-----.
   .' -   - '.
  /  .-. .-.  \
  |  | | | |  |
   \ \o/ \o/ /
  _/    ^    \_
 | \  '---'  / |
 / /`--. .--`\ \
/ /'---` `---'\ \
'.__.       .__.'
    `|     |`
     |     \
     \      '--.
      '.        `\
        `'---.   |
           ,__) /
            `..' 
"""


class Interface(cmd.Cmd):
    prompt = "> "
    intro = BANNER

    def __init__(self):
        super().__init__()

        self.search_result = []
        self.modules = []
        self.current_module = None

        for module_class in utils.others.all_subclasses(module.Module):
            try:
                self.modules.append(module_class())
            except TypeError:
                pass
        print(f"[+] loaded {len(self.modules)} modules")

    def do_search(self, arg):
        """search <tags>; search for modules based on given tags"""

        arg = arg.strip()
        if not arg:
            print("[-] no tags found")
            return

        self.search_result.clear()

        for m in self.modules:
            for tag in arg.split(" "):
                if not any(re.match(tag, t, re.IGNORECASE) for t in m.tags):
                    break
            else:
                print(len(self.search_result), m.name)
                self.search_result.append(m)

    def do_use(self, arg):
        """use <module>; select a given module"""

        try:
            search_index = int(arg)
            self.current_module = self.search_result[search_index]
            self.prompt = f"({self.current_module.name}) > "
            return
        except ValueError:
            pass
        except IndexError:
            print(f"[-] index does not exist")
            return

        for m in self.modules:
            if m.name.casefold() == arg.casefold():
                self.current_module = m
                self.prompt = f"({self.current_module.name}) > "
                return
        print(f"[-] module {arg} does not exist")

    def complete_use(self, text, line, start_index, end_index):
        module_names = [m.name for m in self.modules]
        if text:
            return [name for name in module_names if name.startswith(text)]
        else:
            return module_names

    def do_set(self, arg):
        """set <option> <value>; assign a new value to an option"""

        if not self.current_module:
            print("[-] select a module first")
            return

        name, *value = arg.split(" ")
        try:
            self.current_module.set_option(name, " ".join(value))
        except ValueError as e:
            print(f"[-] {e}")

    def complete_set(self, text, line, start_index, end_index):
        options = list(self.current_module.get_options())
        option_names = [opt.name for opt in options]

        if self.current_module.payload is not None:
            option_names.append("PAYLOAD")

        args = line.split(" ")
        if args[1].upper() not in option_names:  # complete option name
            return [name for name in option_names if name.startswith(text)]
        else:  # complete option value
            if args[1] == "PAYLOAD":
                return [name for name in payloads.names() if name.startswith(text)]

            if len(args) <= 3:
                for option in options:
                    if option.name.casefold() == line.split(" ")[1].casefold():
                        if option.choices is not None:
                            return [choice for choice in option.choices if choice.startswith(text)]
                        if option.type == Type.host or option.type == Type.interface:
                            return [interface for interface in get_if_list() if interface.startswith(text)]
                        if option.type == Type.bool:
                            return [boolean for boolean in ["True", "False"] if boolean.startswith(text)]
                        if option.type == Type.path:
                            paths = glob.glob(args[2] + "*")
                            result = []
                            for path in paths:
                                if os.path.isdir(path):
                                    result.append(path.split(os.sep)[-1] + os.sep)
                                else:
                                    result.append(path.split(os.sep)[-1])
                            return result
                        break
        return []

    def do_unset(self, arg):
        """unset <option>; remove the assigned value of an option"""

        if not self.current_module:
            print("[-] select a module first")
            return

        try:
            self.current_module.unset_option(arg)
        except ValueError as e:
            print(f"[-] {e}")

    def complete_unset(self, text, line, start_index, end_index):
        option_names = [opt.name for opt in self.current_module.options]

        if text:
            return [name for name in option_names if name.startswith(text)]
        else:
            return option_names

    def do_run(self, arg):
        """run; run the currently selected module"""

        if not self.current_module:
            print("[-] select a module first")
            return

        for option in self.current_module.get_options():
            if option.required and not option.is_assigned():
                print("[-] set a value for all required options")
                return

        for option in self.current_module.get_options():
            setattr(self.current_module, option.normalize_name(), option.value)

        try:
            result = self.current_module.run()
            if result is not None:
                session = sessions.Session(*result)
                session.open_shell()
        except PermissionError:
            print("[-] Permission error! You have to run this module as admin!")
        except OSError as e:
            print("[-] OS error:", e)
        except KeyboardInterrupt:
            pass

    def do_options(self, arg):
        """options; prints the options of the currently selected module"""

        if not self.current_module:
            print("[-] select a module first")
            return

        self.current_module.print_options()

    def do_info(self, arg):
        """info; prints the name, tags, description and options of the currently selected module"""

        if not self.current_module:
            print("[-] select a module first")
            return

        self.current_module.print_info()

    def do_sessions(self, arg):
        """sessions; prints a list of all open sessions"""

        if not sessions.count():
            print("[-] no open sessions")
            return

        for i in range(sessions.count()):
            session = sessions.get(i)
            print(f"{i}\t{session.addr[0]}:{session.addr[1]}")

    def do_foreground(self, arg):
        """foreground <session-id>; interact with the given session"""

        try:
            session_id = int(arg)
            if session_id >= sessions.count():
                raise ValueError
        except ValueError:
            print("[-] invalid session id")
            return

        try:
            sessions.get(session_id).open_shell()
        except KeyboardInterrupt:
            pass

    def do_payloads(self, arg):
        """payloads; prints a list of all available payloads"""

        for payload in payloads.names():
            print(payload)

    def do_quit(self, arg):
        """quit; terminates the program"""
        exit(0)

    def do_shell(self, arg):
        """shell <command>; execute shell commands"""
        os.system(arg)

    def emptyline(self):
        return super().emptyline()

    def default(self, line):
        print(f"[-] unknown command {line}")


if __name__ == "__main__":
    try:
        Interface().cmdloop()
    except KeyboardInterrupt:
        pass
