import csv
import os.path
import smtplib
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, formataddr

from module import Module, Type


class PhishingEmail(Module):

    def __init__(self):
        super().__init__("phishing_email",
                         ["phishing", "email"],
                         "send phishing emails")

        self.add_option("HOST", "email server", required=True, type=Type.string)
        self.add_option("PORT", "email server port", required=True, default=25, type=Type.string)
        self.add_option("ACCOUNT", "account used to send the emails", required=True, type=Type.string)
        self.add_option("PASSWORD", "email account password", required=True, type=Type.string)

        self.add_option("NAME", "sender name", required=False, type=Type.string)
        self.add_option("SUBJECT", "email subject", required=False, default="", type=Type.string)
        self.add_option("TEMPLATE", "email template", required=True, type=Type.string)
        self.add_option("TARGETS", "path to a csv file with target data", required=True, type=Type.string)
        self.add_option("TARGET-COLUMN", "column name with the emails in the csv file", required=True, default="email", type=Type.string)
        self.add_option("ATTACHMENT", "path to email attachment", required=False, type=Type.string)

    def run(self):
        if self.attachment is not None and not os.path.isfile(self.attachment):
            print("[-] attachment does not exist")
            return
        if not os.path.isfile(self.template):
            print("[-] template does not exist")
            return
        if not os.path.isfile(self.targets):
            print("[-] targets file does not exist")
            return

        try:
            with smtplib.SMTP(self.host, self.port) as smtp:
                smtp.login(self.account, self.password)

                with open(self.template) as f:
                    template = "".join(f.readlines())

                with open(self.targets) as csvfile:
                    csv_reader = csv.DictReader(csvfile)
                    for row in csv_reader:
                        target = row[self.target_column]

                        msg = MIMEMultipart()
                        msg["From"] = formataddr((self.name, self.account))
                        msg["To"] = target
                        msg["Date"] = formatdate(localtime=True)
                        msg["Subject"] = self.subject

                        text = template
                        for col, value in row.items():
                            text = text.replace(f"^{col}^", value)
                        msg.attach(MIMEText(text))

                        if self.attachment is not None:
                            part = MIMEBase("application", "octet-stream")
                            with open(self.attachment, "rb") as f:
                                part.set_payload(f.read())
                            encoders.encode_base64(part)
                            part.add_header("Content-Disposition", f"attachment; filename={os.path.basename(self.attachment)}")

                            smtp.sendmail(self.account, target, msg.as_string())
        except smtplib.SMTPAuthenticationError:
            print("[-] invalid credentials")
