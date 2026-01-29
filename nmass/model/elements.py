import csv
from datetime import datetime
from io import BufferedWriter
from typing import Literal
from urllib.request import urlopen

import lxml.etree as ET
from pydantic import field_validator
from pydantic_xml import BaseXmlModel, RootXmlModel, attr, element, wrapped
from typing_extensions import Self

from .enums import HostState, PortProtocol, PortState, ScanType


class CPE(RootXmlModel[str]):
    def __str__(self) -> str:
        return self.root

    @property
    def part(self) -> str:
        return self.root.split(":")[1]

    @property
    def vendor(self) -> str:
        return self.root.split(":")[2]

    @property
    def product(self) -> str:
        return self.root.split(":")[3]

    @property
    def version(self) -> str:
        try:
            return self.root.split(":")[4]
        except IndexError:
            return ""

    @property
    def update(self) -> str:
        try:
            return self.root.split(":")[5]
        except IndexError:
            return ""

    @property
    def edition(self) -> str:
        try:
            return self.root.split(":")[6]
        except IndexError:
            return ""

    @property
    def language(self) -> str:
        try:
            return self.root.split(":")[7]
        except IndexError:
            return ""


class ScanInfo(BaseXmlModel, tag="scaninfo"):
    type: ScanType = attr()
    protocol: PortProtocol = attr()
    numservices: int | None = attr(default=None)  # None in masscan
    services: str | None = attr(default=None)  # None in masscan
    scanflags: str | None = attr(default=None)


class Service(BaseXmlModel, tag="service"):
    name: str = attr()
    banner: str | None = attr(default=None)  # masscan
    product: str | None = attr(default=None)
    version: str | None = attr(default=None)
    method: Literal["table", "probed"] | None = attr(default=None)
    confidence: int | None = attr(name="conf", default=None)  # None in masscan
    extrainfo: str | None = attr(default=None)
    tunnel: str | None = attr(default=None)
    proto: str | None = attr(default=None)
    rpcnum: int | None = attr(default=None)
    lowver: int | None = attr(default=None)
    highver: int | None = attr(default=None)
    hostname: str | None = attr(default=None)
    ostype: str | None = attr(default=None)
    devicetype: str | None = attr(default=None)
    servicefp: str | None = attr(default=None)
    cpe: CPE | None = element(default=None)


class ScriptElement(BaseXmlModel, tag="elem"):
    key: str | None = attr(default=None)
    value: str | None = None


class ScriptTable(BaseXmlModel, tag="table"):
    key: str | None = attr(default=None)
    items: list[Self | ScriptElement] = element(default=[])


class Script(BaseXmlModel, tag="script"):
    id: str = attr()
    output: str = attr()
    tables: list[ScriptTable] = element(default=[])
    elements: list[ScriptElement] = element(default=[])


class Port(BaseXmlModel, tag="port"):
    class State(BaseXmlModel, tag="state"):
        state: PortState = attr()
        reason: str = attr()
        reason_ttl: str = attr()
        reason_ip: str | None = attr(default=None)

    class Owner(BaseXmlModel, tag="owner"):
        name: str = attr()

    protocol: PortProtocol = attr()
    portid: int = attr()
    state: State
    owner: Owner | None = element(default=None)
    service: Service | None = element(default=None)
    scripts: list[Script] = element(default=[])

    @property
    def port_state(self) -> PortState:
        """Port state (open, closed, filtered, etc.)"""
        return self.state.state

    @property
    def reason(self) -> str:
        """Reason for the port state"""
        return self.state.reason

    @property
    def is_open(self) -> bool:
        """Check if the port is open"""
        return self.state.state == PortState.open

    @property
    def service_name(self) -> str | None:
        """Service name detected on this port"""
        return self.service.name if self.service else None

    @property
    def product(self) -> str | None:
        """Product name detected on this port"""
        return self.service.product if self.service else None

    @property
    def service_product(self) -> str | None:
        """Product name detected on this port (alias for product)"""
        return self.service.product if self.service else None

    @property
    def version(self) -> str | None:
        """Version of the service/product detected"""
        return self.service.version if self.service else None

    @property
    def service_version(self) -> str | None:
        """Version of the service/product detected (alias for version)"""
        return self.service.version if self.service else None


class PortUsed(BaseXmlModel, tag="portused"):
    state: PortState = attr()
    proto: PortProtocol = attr()
    portid: int = attr()


class ExtraPorts(BaseXmlModel, tag="extraports"):
    class ExtraReason(BaseXmlModel, tag="extrareasons"):
        reason: str = attr()
        count: int = attr()
        proto: PortProtocol | None = attr(default=None)
        ports: str | None = attr(default=None)

    state: PortState = attr()
    count: int = attr()
    extrareasons: list[ExtraReason] = element()


class Ports(BaseXmlModel, tag="ports"):
    extraports: list[ExtraPorts] = element(default=[])
    ports: list[Port] = element(default=[])


class Hostname(BaseXmlModel, tag="hostname"):
    name: str = attr()
    type: Literal["user", "PTR"] = attr()


class OSClass(BaseXmlModel, tag="osclass"):
    type: str | None = attr(default=None)
    vendor: str = attr()
    osfamily: str = attr()
    osgen: str | None = attr(default=None)
    accuracy: int = attr()
    cpe: CPE | None = element(default=None)


class OSMatch(BaseXmlModel, tag="osmatch"):
    name: str = attr()
    accuracy: int = attr()
    line: int = attr()
    osclasses: list[OSClass]


class OS(BaseXmlModel, tag="os"):
    class OSFingerprint(BaseXmlModel, tag="osfingerprint"):
        fingerprint: str = attr()

    used_ports: list[PortUsed] | None = element(default=None)
    osmatches: list[OSMatch] | None = element(default=None)
    osfingerprint: OSFingerprint | None = element(default=None)

    @property
    def fingerprint(self) -> str | None:
        return self.osfingerprint.fingerprint if self.osfingerprint else None


class Trace(BaseXmlModel, tag="trace"):
    pass


class Address(BaseXmlModel, tag="address"):
    addr: str = attr()
    addrtype: Literal["ipv4", "ipv6", "mac"] = attr()
    vendor: str | None = attr(default=None)


class Host(BaseXmlModel, tag="host"):
    class Status(BaseXmlModel, tag="status"):
        state: HostState = attr()
        reason: str = attr()
        reason_ttl: int | None = attr(default=None)

    starttime: datetime | None = attr(default=None)
    endtime: datetime | None = attr(default=None)
    timeout: bool | None = attr(default=None)
    comment: str | None = attr(default=None)
    status: Status | None = element(default=None)  # None in masscan
    addresses: list[Address]
    hostnames: list[Hostname] = wrapped("hostnames", element(tag="hostname", default=[]))
    ports: Ports | None = element(default=None)
    os: OS | None = element(default=None)
    uptime: dict[str, str] | None = element(default=None)
    distance: dict[str, int] | None = element(default=None)
    tcpsequence: dict[str, str] | None = element(default=None)
    ipidsequence: dict[str, str] | None = element(default=None)
    tcptssequence: dict[str, str] | None = element(default=None)
    trace: Trace | None = element(default=None)
    times: dict[str, int] | None = element(default=None)

    @field_validator("starttime", "endtime", mode="before")
    def decode_timestamp(cls, value: str | None) -> datetime | None:
        return datetime.fromtimestamp(int(value)) if value else None

    @property
    def state(self) -> HostState | None:
        """Host state (up, down, etc.)"""
        return self.status.state if self.status else None

    @property
    def port_list(self) -> list[Port]:
        """List of scanned ports (flattened from ports.ports)"""
        return self.ports.ports if self.ports else []

    @property
    def extra_ports(self) -> list[ExtraPorts]:
        """Extra ports information"""
        return self.ports.extraports if self.ports else []

    @property
    def address(self) -> Address | None:
        """Primary address of the host"""
        return self.addresses[0] if self.addresses else None

    @property
    def ipv4(self) -> str | None:
        """IPv4 address of the host"""
        for addr in self.addresses:
            if addr.addrtype == "ipv4":
                return addr.addr
        return None

    @property
    def ip(self) -> str | None:
        """Primary IP address of the host (IPv4 if available, otherwise IPv6)"""
        return self.ipv4 or self.ipv6

    @property
    def ipv6(self) -> str | None:
        """IPv6 address of the host"""
        for addr in self.addresses:
            if addr.addrtype == "ipv6":
                return addr.addr
        return None

    @property
    def mac(self) -> str | None:
        """MAC address of the host"""
        for addr in self.addresses:
            if addr.addrtype == "mac":
                return addr.addr
        return None

    @property
    def hostname(self) -> str | None:
        """Primary hostname of the host"""
        return self.hostnames[0].name if self.hostnames else None

    @property
    def os_matches(self) -> list[OSMatch] | None:
        """OS detection matches (flattened from os.osmatches)"""
        return self.os.osmatches if self.os else None

    @property
    def os_name(self) -> str | None:
        """Name of the first OS match (most likely OS)"""
        if self.os and self.os.osmatches:
            return self.os.osmatches[0].name
        return None

    @property
    def open_ports(self) -> list[Port]:
        """List of ports that are in the open state"""
        if not self.ports or not self.ports.ports:
            return []
        return [p for p in self.ports.ports if p.state and p.state.state == PortState.open]


class HostHint(BaseXmlModel, tag="hosthint"):
    status: Host.Status = element()
    address: list[Address]
    hostnames: list[Hostname] = wrapped("hostnames", element(tag="hostname", default=[]))


class TaskProgress(BaseXmlModel, tag="taskprogress"):
    task: str = attr()
    time: datetime = attr()
    percent: float = attr()
    remaining: int | None = attr(default=None)
    etc: str | None = attr(default=None)

    @field_validator("time", mode="before")
    def decode_timestamp(cls, value: str) -> datetime:
        return datetime.fromtimestamp(int(value))


class NmapRun(BaseXmlModel, tag="nmaprun", search_mode="ordered"):
    """
    This is the data model that maps with the Nmap (also Masscan) XML output.
    Refer to https://nmap.org/book/nmap-dtd.html for details.
    """

    class Stats(BaseXmlModel, tag="runstats"):
        finished: dict[str, str] = element()
        hosts: dict[str, int] = element()

    scanner: Literal["nmap", "masscan"] = attr()
    args: str | None = attr(default=None)
    start: int | None = attr(default=None)
    start_time: datetime | None = attr(name="startstr", default=None)
    version: str = attr()
    profile_name: str | None = attr(default=None)
    xmloutputversion: str = attr()

    @field_validator("start_time", mode="before")
    def decode_timestr(cls, value: str | None) -> datetime | None:
        return datetime.strptime(value, "%a %b %d %H:%M:%S %Y") if value else None

    # https://seclists.org/nmap-dev/2005/q1/77
    scaninfo: list[ScanInfo] | None = element(default=None)
    verbose: dict[str, int] | None = element(default=None)  # None in masscan
    debugging: dict[str, int] | None = element(default=None)  # None in masscan
    hosthint: HostHint | None = element(default=None)
    taskprogress: list[TaskProgress] | None = element(default=None)
    hosts: list[Host] = element(default=[])
    stats: Stats | None = element(default=None)

    # Convenience properties for better UX
    @property
    def host_stats(self) -> dict[str, int] | None:
        """Statistics about scanned hosts (up, down, total)"""
        return self.stats.hosts if self.stats else None

    @property
    def scan_stats(self) -> dict[str, int] | None:
        """Statistics about scanned hosts (alias for host_stats)"""
        return self.stats.hosts if self.stats else None

    @property
    def finished(self) -> dict[str, str] | None:
        """Scan finish information (time, summary, etc.)"""
        return self.stats.finished if self.stats else None

    @property
    def hosts_up(self) -> int:
        """Number of hosts that are up"""
        return self.host_stats.get("up", 0) if self.host_stats else 0

    @property
    def hosts_down(self) -> int:
        """Number of hosts that are down"""
        return self.host_stats.get("down", 0) if self.host_stats else 0

    @property
    def hosts_total(self) -> int:
        """Total number of hosts scanned"""
        return self.host_stats.get("total", 0) if self.host_stats else 0

    @property
    def up_hosts(self) -> list[Host]:
        """List of hosts that are in the up state"""
        return [h for h in self.hosts if h.status and h.status.state == HostState.up]

    @property
    def down_hosts(self) -> list[Host]:
        """List of hosts that are in the down state"""
        return [h for h in self.hosts if h.status and h.status.state == HostState.down]

    @property
    def total_hosts(self) -> int:
        """Total number of hosts in the scan results"""
        return len(self.hosts)

    def to_html(self, xslt_path: str = "https://nmap.org/svn/docs/nmap.xsl", pretty_print: bool = False) -> str:
        # https://stackoverflow.com/a/34035675
        xslt = ET.parse(urlopen(xslt_path, timeout=10)) if xslt_path.startswith("https://") else ET.parse(xslt_path)
        transform = ET.XSLT(xslt)
        newdom = transform(self.to_xml_tree())  # type: ignore
        return ET.tostring(newdom, pretty_print=pretty_print).decode()

    def to_csv_file(self, file: BufferedWriter, dialect: str | csv.Dialect = "excel") -> None:
        """Write information to a CSV file.

        :param file: A file-like object where the CSV data will be written
        :param dialect: The CSV dialect used for formatting the file, defaults to "excel"
        """
        writer = csv.writer(file, dialect=dialect)  # type: ignore
        writer.writerow(["IP", "Port", "Protocol", "State", "Service", "Reason", "Product", "Version", "CPE"])
        for host in self.hosts:
            host_info = host.addresses[0].addr
            if host.status is not None:
                host_info += f" ({host.status.state})"
            writer.writerow([host_info, "", "", "", "", "", "", "", ""])

            if host.ports is None or host.ports.ports is None:
                continue

            for port in host.ports.ports:
                writer.writerow([
                    "",
                    str(port.portid),
                    port.protocol,
                    port.state.state,
                    port.service.name if port.service else "",
                    port.state.reason,
                    port.service.product if port.service else "",
                    port.service.version if port.service else "",
                    str(port.service.cpe) if port.service else "",
                ])
