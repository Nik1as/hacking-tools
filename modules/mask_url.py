import requests

from module import Module, Type


class MaskURL(Module):

    def __init__(self):
        super().__init__("mask_url",
                         ["mask", "url", "phishing"],
                         "mask a url")

        self.add_option("URL", "url to be masked", required=True, type=Type.string)
        self.add_option("MASK", "masking domain", required=True, type=Type.string)
        self.add_option("KEYWORD", "keyword", required=False, type=Type.string)

    def run(self):
        response = requests.get(f"https://is.gd/create.php?format=json&url={self.url}")
        short_url = response.json()["shorturl"].lstrip("https://")

        if self.keyword is None:
            print(f"https://{self.mask}@{short_url}")
        else:
            print(f"https://{self.mask}-{self.keyword}@{short_url}")
