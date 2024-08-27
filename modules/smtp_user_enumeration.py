import smtplib

from module import Module, Type
from utils.others import read_wordlist


class SMTPUserEnumeration(Module):

    def __init__(self):
        super().__init__("smtp_user_enumeration",
                         ["smtp", "user", "enumeration"],
                         "enumerate smtp emails")

        self.add_option("RHOST", "target host", required=True, type=Type.host)
        self.add_option("RPORT", "target port", required=True, default=25, type=Type.int)
        self.add_option("WORDLIST", "path to a wordlist of emails", required=True, type=Type.path)

    def run(self):
        try:
            smtp = smtplib.SMTP()

            smtp.connect(self.rhost, self.rport)
            smtp.ehlo("mail.example.com")

            if smtp.has_extn("vrfy"):
                check = smtp.vrfy
            elif smtp.has_extn("expn"):
                check = smtp.expn
            else:
                smtp.mail("user@example.com")
                check = smtp.rcpt

            for user in read_wordlist(self.wordlist):
                code, _ = check(user)
                if code in (250, 251, 252):
                    print(f"[+] user found: {user}\t status: {code}")
        except (smtplib.SMTPDataError, smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, smtplib.SMTPSenderRefused):
            print("[-] error while enumerating users")
