import hashlib
import json

import requests

from modules.portscanner.scripts import Script
from utils.network import Protocol
from utils.web import get_url


class HTTPFavicon(Script):

    def __init__(self):
        super().__init__("http", Protocol.TCP)

    async def run(self, host: str, state):
        response = requests.get(get_url(host, state.port, "/favicon.ico"))
        if response.status_code == 200:
            favicon_hash = hashlib.md5(response.content).hexdigest()

            # https://raw.githubusercontent.com/OWASP/www-community/master/_data/favicons-database.yml
            with open("data/favicon-database.json") as f:
                database = json.load(f)
                for entry in database:
                    if entry["hash"] == favicon_hash:
                        state.scripts.append(f"favicon: {entry["name"]}")
                        break
                else:
                    print(favicon_hash)
                    state.scripts.append(f"favicon: {favicon_hash}")
