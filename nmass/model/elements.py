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
    extraports: ExtraPorts | None = element(default=None)
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
