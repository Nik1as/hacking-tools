import asyncio
import enum
import ipaddress
import socket
from abc import ABC, abstractmethod

from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.main import load_module
from scapy.modules.nmap import nmap_fp
from scapy.sendrecv import sr
from scapy.sendrecv import sr1
from scapy.volatile import RandShort

from module import Module, Type
from modules.portscanner.scripts import Script
from modules.portscanner.services import ServiceDetection
from modules.portscanner.versions import VersionDetection
from utils.network import Protocol
from utils.network import get_service_by_port
from utils.others import all_subclasses

load_module("nmap")


class PortState(enum.Enum):
    OPEN = "open",
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED = "closed"
    UNKNOWN_RESPONSE = "unknown response"
    UNANSWERED = "unanswered"


class PortResult:

    def __init__(self, port: int, state: PortState = PortState.CLOSED):
        self.port = port
        self.state = state
        self.service = ""
        self.version = ""
        self.scripts = []


class Scan(ABC):

    def __init__(self, name: str, protocol: Protocol, exclude: PortState):
        self.name = name
        self.protocol = protocol
        self.exclude = exclude

    @abstractmethod
    def run(self, host: str, ports: list[int], timeout: float, retries: int) -> list[PortResult]:
        pass


class SYNScan(Scan):

    def __init__(self):
        super().__init__("SYN", Protocol.TCP, PortState.CLOSED)

    def run(self, host: str, ports: list[int], timeout: float, retries: int) -> list[PortResult]:
        results = []

        packets = IP(dst=host) / TCP(sport=RandShort(), dport=ports, flags="S")
        ans, unans = sr(packets, timeout=timeout, verbose=False, retry=retries)

        for pkt in unans:
            results.append(PortResult(port=pkt[TCP].dport, state=PortState.UNANSWERED))

        for probe, response in ans:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x12:  # SYN-ACK
                    results.append(PortResult(port=probe[TCP].dport, state=PortState.OPEN))
                elif response[TCP].flags == 0x14:  # RST-ACK
                    results.append(PortResult(port=probe[TCP].dport, state=PortState.CLOSED))
                else:
                    results.append(PortResult(port=probe[TCP].dport, state=PortState.FILTERED))
            elif response.haslayer(ICMP):
                results.append(PortResult(port=probe[TCP].dport, state=PortState.FILTERED))
            else:
                results.append(PortResult(port=probe[TCP].dport, state=PortState.UNKNOWN_RESPONSE))
        return results


class ACKScan(Scan):

    def __init__(self):
        super().__init__("ACK", Protocol.TCP, PortState.CLOSED)

    def run(self, host: str, ports: list[int], timeout: float, retries: int) -> list[PortResult]:
        results = []

        packets = IP(dst=host) / TCP(sport=RandShort(), dport=ports, flags="A")
        ans, unans = sr(packets, timeout=timeout, verbose=False, retry=retries)

        for pkt in unans:
            results.append(PortResult(port=pkt[TCP].dport, state=PortState.FILTERED))

        for probe, response in ans:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x14:  # RST-ACK
                    results.append(PortResult(port=probe[TCP].dport, state=PortState.UNFILTERED))
                else:
                    results.append(PortResult(port=probe[TCP].dport, state=PortState.FILTERED))
            elif response.haslayer(ICMP):
                results.append(PortResult(port=probe[TCP].dport, state=PortState.FILTERED))
            else:
                results.append(PortResult(port=probe[TCP].dport, state=PortState.UNKNOWN_RESPONSE))
        return results


class FINScan(Scan):

    def __init__(self):
        super().__init__("FIN", Protocol.TCP, PortState.CLOSED)

    def run(self, host: str, ports: list[int], timeout: float, retries: int) -> list[PortResult]:
        results = []

        packets = IP(dst=host) / TCP(sport=RandShort(), dport=ports, flags="F")
        ans, unans = sr(packets, timeout=timeout, verbose=False, retry=retries)

        for pkt in unans:
            results.append(PortResult(port=pkt[TCP].dport, state=PortState.OPEN))

        for probe, response in ans:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x14:  # RST-ACK
                    results.append(PortResult(port=probe[TCP].dport, state=PortState.CLOSED))
                else:
                    results.append(PortResult(port=probe[TCP].dport, state=PortState.FILTERED))
            elif response.haslayer(ICMP):
                results.append(PortResult(port=probe[TCP].dport, state=PortState.FILTERED))
            else:
                results.append(PortResult(port=probe[TCP].dport, state=PortState.UNKNOWN_RESPONSE))
        return results


class NULLScan(Scan):

    def __init__(self):
        super().__init__("NULL", Protocol.TCP, PortState.CLOSED)

    def run(self, host: str, ports: list[int], timeout: float, retries: int) -> list[PortResult]:
        results = []

        packets = IP(dst=host) / TCP(sport=RandShort(), dport=ports, flags="")
        ans, unans = sr(packets, timeout=timeout, verbose=False, retry=retries)

        for pkt in unans:
            results.append(PortResult(port=pkt[TCP].dport, state=PortState.OPEN))

        for probe, response in ans:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x14:  # RST-ACK
                    results.append(PortResult(port=probe[TCP].dport, state=PortState.CLOSED))
                else:
                    results.append(PortResult(port=probe[TCP].dport, state=PortState.FILTERED))
            elif response.haslayer(ICMP):
                results.append(PortResult(port=probe[TCP].dport, state=PortState.FILTERED))
            else:
                results.append(PortResult(port=probe[TCP].dport, state=PortState.UNKNOWN_RESPONSE))
        return results


class XMASScan(Scan):

    def __init__(self):
        super().__init__("XMAS", Protocol.TCP, PortState.CLOSED)

    def run(self, host: str, ports: list[int], timeout: float, retries: int) -> list[PortResult]:
        results = []

        packets = IP(dst=host) / TCP(sport=RandShort(), dport=ports, flags="FPU")
        ans, unans = sr(packets, timeout=timeout, verbose=False, retry=retries)

        for pkt in unans:
            results.append((pkt[TCP].dport, PortState.OPEN_FILTERED))

        for probe, response in ans:
            if response.haslayer(TCP):
                if response[TCP].flags == 0x14:  # RST-ACK
                    results.append(PortResult(port=probe[TCP].dport, state=PortState.CLOSED))
                else:
                    results.append(PortResult(port=probe[TCP].dport, state=PortState.OPEN))
            elif response.haslayer(ICMP):
                results.append(PortResult(port=probe[TCP].dport, state=PortState.FILTERED))
            else:
                results.append(PortResult(port=probe[TCP].dport, state=PortState.UNKNOWN_RESPONSE))
        return results


class UDPScan(Scan):

    def __init__(self):
        super().__init__("XMAS", Protocol.UDP, PortState.CLOSED)

    def run(self, host: str, ports: list[int], timeout: float, retries: int) -> list[PortResult]:
        results = []

        pkt = IP(dst=host) / UDP(sport=RandShort(), dport=ports)
        ans, unans = sr(pkt, timeout=timeout, verbose=False, retry=retries)

        for pkt in unans:
            results.append(PortResult(port=pkt[UDP].dport, state=PortState.OPEN_FILTERED))

        for probe, response in ans:
            if response.haslayer(ICMP):
                results.append(PortResult(port=probe[UDP].dport, state=PortState.CLOSED))
            elif response.haslayer(UDP):
                results.append(PortResult(port=probe[UDP].dport, state=PortState.OPEN_FILTERED))
            else:
                results.append(PortResult(port=probe[UDP].dport, state=PortState.UNKNOWN_RESPONSE))
        return results


SCANS = [scan_class() for scan_class in all_subclasses(Scan)]
SCANS = {scan.name: scan for scan in SCANS}


class PortScanner(Module):

    def __init__(self):
        super().__init__("portscanner",
                         ["portscanner", "service", "discovery", "version", "detection", "os"],
                         "advanced port scanner")

        self.add_option("RHOSTS", "target hosts", required=True, type=Type.host)
        self.add_option("RPORTS", "target ports", required=True, default=list(range(1, 2 ** 16)), type=Type.int_list_or_range)
        self.add_option("MODE", "scan mode", required=True, default="SYN", type=Type.string, choices=list(SCANS.keys()))
        self.add_option("VERSION-DETECTION", "perform service and version detection", required=True, default=False, type=Type.bool)
        self.add_option("SCRIPTS", "run scripts", required=True, default=False, type=Type.bool)
        self.add_option("OS-DETECTION", "os detection", required=True, default=False, type=Type.bool)
        self.add_option("PING-CHECK", "check if a host is alive", required=True, default=False, type=Type.bool)
        self.add_option("TIMEOUT", "timeout", required=True, default=20, type=Type.float)
        self.add_option("RETRIES", "retries", required=True, default=6, type=Type.float)

    def run(self):
        socket.setdefaulttimeout(self.timeout)
        hosts = self.rhosts

        try:
            hosts = socket.gethostbyname(hosts)
        except socket.gaierror:
            pass

        for ip in ipaddress.IPv4Network(hosts, False).hosts():
            asyncio.run(self.scan_host(str(ip)))

    async def scan_host(self, host: str):
        if self.ping_check:
            icmp = IP(dst=host) / ICMP()
            resp = sr1(icmp, timeout=self.timeout, verbose=False)
            if resp is None:
                return

        print(f"===== scan host {host} ====")

        results_all = self.scan().run(host, self.rports, self.timeout, self.retries)
        results = list(filter(lambda result: result.state != self.scan().exclude, results_all))
        results.sort(key=lambda r: r.port)

        service_detectors = [service_class() for service_class in all_subclasses(ServiceDetection)]
        version_detectors = [version_class() for version_class in all_subclasses(VersionDetection)]
        scripts = [script_class() for script_class in all_subclasses(Script)]

        tasks = [detector.run(host, result)
                 for detector in service_detectors
                 for result in results
                 if result.port in detector.ports and detector.protocol == self.protocol()]
        await asyncio.gather(*tasks)

        tasks = [detector.run(host, result)
                 for detector in service_detectors
                 for result in results
                 if not result.service and detector.protocol == self.protocol()]
        await asyncio.gather(*tasks)

        for result in results:
            if not result.service:
                result.service = get_service_by_port(result.port, self.protocol())

        if self.version_detection:
            tasks = [detector.run(host, result)
                     for detector in version_detectors
                     for result in results
                     if detector.service == result.service and detector.protocol == self.protocol()]
            await asyncio.gather(*tasks)

        if self.scripts:
            tasks = [script.run(host, result)
                     for script in scripts
                     for result in results
                     if script.service == result.service and script.protocol == self.protocol()]
            await asyncio.gather(*tasks)

        print(f"{'PORT'.ljust(8)}{'STATE'.ljust(15)}{'SERVICE'.ljust(30)}VERSION")
        for result in results:
            print(f"{str(result.port).ljust(8)}{result.state.value[0].ljust(15)}{result.service.ljust(30)}{result.version}")
            if result.scripts:
                for script in result.scripts:
                    print(script)

        if self.os_detection:
            self.detect_os(host, results_all)

    def detect_os(self, ip: str, scan_results: list):
        open_port = None
        closed_port = None
        for port, state, _, _ in scan_results:
            if state == PortState.OPEN:
                open_port = port
            elif state == PortState.CLOSED:
                closed_port = port

        if open_port is None or closed_port is None:
            print("[-] os scan needs at least one open and one closed port!")
            return

        try:
            nmap_fp(ip, oport=open_port, cport=closed_port)
        except TypeError:
            print("[-] os scan needs nmap!")

    def protocol(self):
        return self.scan().protocol

    def scan(self):
        return SCANS[self.mode]
