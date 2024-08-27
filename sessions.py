import select
import socket
import sys
import threading

sessions = []


def get(id: int):
    return sessions[id]


def count():
    return len(sessions)


BUFFER_SIZE = 4096


class Session:

    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        sessions.append(self)

    def open_shell(self):
        pill2kill = threading.Event()
        recv_thread = threading.Thread(target=self.recv, args=(pill2kill,))
        recv_thread.start()

        try:
            while True:
                command = input()
                self.conn.send((command + "\n").encode())
        except KeyboardInterrupt:
            pass
        except BrokenPipeError:
            sessions.remove(self)

        pill2kill.set()
        recv_thread.join()

    def recv(self, stop_event: threading.Event):
        self.conn.settimeout(0.3)
        while not stop_event.wait(0.3):
            try:
                data = self.conn.recv(BUFFER_SIZE)
                data = data.decode()
                if data:
                    sys.stdout.write(data)
            except TimeoutError:
                pass

    def close(self):
        self.conn.close()
        sessions.remove(self)


class Listener(threading.Thread):

    def __init__(self, ip: str, port: int):
        super().__init__()
        self.ip = ip
        self.port = port
        self.conn = None
        self.addr = None
        self.stopped = False

    def run(self):
        print(f"[+] listen on {self.ip}:{self.port}")
        self.stopped = False

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.ip, self.port))
            server_socket.listen(1)

            while True:
                readable, writable, errored = select.select([server_socket], [], [])
                for s in readable:
                    if s is server_socket:
                        conn, addr = server_socket.accept()
                        if not self.stopped:
                            self.conn = conn
                            self.addr = addr
                            print(f"[+] connection received from {self.addr[0]}:{self.addr[1]}")
                        return

    def stop(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                self.stopped = True
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.connect((self.ip, self.port))
        except ConnectionRefusedError:
            pass

    def connected(self):
        return self.conn is not None

    def get(self):
        return self.conn, self.addr
