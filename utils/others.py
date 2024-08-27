import importlib
import os
import pkgutil


def append_slash_if_dir(path: str) -> str:
    if path and os.path.isdir(path) and path[-1] != os.sep:
        return path + os.sep
    else:
        return path


def read_wordlist(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f.readlines():
            line = line.strip()
            if not line.startswith("#"):
                yield line


def get_not_none(iterable):
    return [x for x in iterable if x is not None]


def print_table(data: list, headers: list = None):
    if not data:
        return

    num_columns = len(data[0])
    column_widths = [max(len(str(row[i])) for row in data) for i in range(num_columns)]

    if headers:
        column_widths = [max(column_widths[i], len(headers[i])) for i in range(num_columns)]
        print("   ".join(str(headers[i]).ljust(column_widths[i]) for i in range(num_columns)))
        print("   ".join(("-" * len(headers[i])).ljust(column_widths[i]) for i in range(num_columns)))

    for row in data:
        print("   ".join(str(row[i]).ljust(column_widths[i]) for i in range(num_columns)))


def xor(a: bytes, b: bytes):
    return bytes([x ^ y for x, y in zip(a, b)])


def all_subclasses(cls):
    return set(cls.__subclasses__()).union(
        [s for c in cls.__subclasses__() for s in all_subclasses(c)])


def import_submodules(package, recursive=True):
    if isinstance(package, str):
        package = importlib.import_module(package)
    results = {}
    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__):
        full_name = package.__name__ + '.' + name
        try:
            results[full_name] = importlib.import_module(full_name)
        except ModuleNotFoundError:
            continue
        if recursive and is_pkg:
            results.update(import_submodules(full_name))
    return results
