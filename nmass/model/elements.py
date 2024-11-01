import csv
from io import BufferedWriter
from typing import Literal, Optional, Union
from urllib.request import urlopen

import lxml.etree as ET
from pydantic_xml import BaseXmlModel, RootXmlModel, attr, element, wrapped

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
    numservices: Optional[int] = attr(default=None)
    services: Optional[str] = attr(default=None)


class Service(BaseXmlModel, tag="service"):
    name: str = attr()
    banner: Optional[str] = attr(default=None)  # for masscan
    product: Optional[str] = attr(default=None)
    version: Optional[str] = attr(default=None)
    method: Optional[Literal["table", "probed"]] = attr(default=None)
    confidence: Optional[int] = attr(name="conf", default=None)
    cpe: Optional[CPE] = element(default=None)


class Script(BaseXmlModel, tag="script"):
    id: str = attr()
    output: str = attr()


class Port(BaseXmlModel, tag="port"):
    class State(BaseXmlModel, tag="state"):
        state: PortState = attr()
        reason: str = attr()
        reason_ttl: str = attr()

    protocol: PortProtocol = attr()
    portid: int = attr()
    state: State
    service: Optional[Service] = element(default=None)
    scripts: Optional[list[Script]] = element(default=None)


class PortUsed(BaseXmlModel, tag="portused"):
    state: PortState = attr()
    proto: PortProtocol = attr()
    portid: int = attr()


class ExtraPorts(BaseXmlModel, tag="extraports"):
    class ExtraReasons(BaseXmlModel, tag="extrareasons"):
        reason: str = attr()
        count: int = attr()

    state: PortState = attr()
    count: int = attr()
    reasons: ExtraReasons = element()


class Ports(BaseXmlModel, tag="ports"):
    extraports: Optional[ExtraPorts] = element(default=None)
    ports: Optional[list[Port]] = element(default=None)


class Hostname(BaseXmlModel, tag="hostname"):
    name: str = attr()
    type: Literal["user", "PTR"] = attr()


class OSClass(BaseXmlModel, tag="osclass"):
    type: str = attr(default="")
    vendor: str = attr()
    osfamily: str = attr()
    osgen: str = attr(default="")
    accuracy: int = attr()
    cpe: Optional[CPE] = element(default=None)


class OSMatch(BaseXmlModel, tag="osmatch"):
    name: str = attr()
    accuracy: int = attr()
    line: int = attr()
    osclasses: list[OSClass]


class OS(BaseXmlModel, tag="os"):
    used_ports: Optional[list[PortUsed]] = element(default=None)
    osmatches: Optional[list[OSMatch]] = element(default=None)


class Trace(BaseXmlModel, tag="trace"):
    pass


class Address(BaseXmlModel, tag="address"):
    addr: str = attr()
    addrtype: Literal["ipv4", "ipv6", "mac"] = attr()


class Host(BaseXmlModel, tag="host"):
    class Status(BaseXmlModel, tag="status"):
        state: HostState = attr()
        reason: str = attr()
        reason_ttl: Optional[str] = attr(default=None)

    status: Optional[Status] = element(default=None)  # None for masscan
    address: list[Address]
    hostnames: list[Hostname] = wrapped("hostnames", element(tag="hostname", default=[]))  # type: ignore
    ports: Optional[Ports] = element(default=None)
    os: Optional[OS] = element(default=None)
    uptime: Optional[dict[str, str]] = element(default=None)
    distance: Optional[dict[str, int]] = element(default=None)
    tcpsequence: Optional[dict[str, str]] = element(default=None)
    ipidsequence: Optional[dict[str, str]] = element(default=None)
    tcptssequence: Optional[dict[str, str]] = element(default=None)
    trace: Optional[Trace] = element(default=None)
    times: Optional[dict[str, int]] = element(default=None)


class HostHint(BaseXmlModel, tag="hosthint"):
    status: Host.Status = element()
    address: list[Address]
    hostnames: list[Hostname] = wrapped("hostnames", element(tag="hostname", default=[]))  # type: ignore


class TaskProgress(BaseXmlModel, tag="taskprogress"):
    task: str = attr()
    time: str = attr()
    percent: float = attr()
    remaining: Optional[int] = attr(default=None)
    etc: Optional[str] = attr(default=None)


class NmapRun(BaseXmlModel, tag="nmaprun", search_mode="ordered"):
    """
    This is the data model that maps with the Nmap (also Masscan) XML output.
    Refer to https://nmap.org/book/nmap-dtd.html for details.
    """

    class Stats(BaseXmlModel, tag="runstats"):
        finished: dict[str, str] = element()
        hosts: dict[str, int] = element()

    scanner: Literal["nmap", "masscan"] = attr()
    args: Optional[str] = attr(default=None)
    start: Optional[int] = attr(default=None)
    start_time: Optional[str] = attr(name="startstr", default=None)
    version: str = attr()
    xmloutputversion: str = attr()

    # https://seclists.org/nmap-dev/2005/q1/77
    scaninfo: Optional[ScanInfo] = element(default=None)
    verbose: Optional[dict[str, int]] = element(default=None)  # None for masscan
    debugging: Optional[dict[str, int]] = element(default=None)  # None for masscan
    hosthint: Optional[HostHint] = element(default=None)
    taskprogress: Optional[list[TaskProgress]] = element(default=None)
    hosts: list[Host] = element(default=[])
    stats: Optional[Stats] = element(default=None)

    def to_html(self, xslt_path: str = "https://nmap.org/svn/docs/nmap.xsl", pretty_print: bool = False) -> str:
        # https://stackoverflow.com/a/34035675
        xslt = ET.parse(urlopen(xslt_path, timeout=10)) if xslt_path.startswith("https://") else ET.parse(xslt_path)
        transform = ET.XSLT(xslt)
        newdom = transform(self.to_xml_tree())  # type: ignore
        return ET.tostring(newdom, pretty_print=pretty_print).decode()

    def to_csv_file(self, file: BufferedWriter, dialect: Union[str, csv.Dialect] = "excel") -> None:
        """Write information to a CSV file.

        :param file: A file-like object where the CSV data will be written
        :param dialect: The CSV dialect used for formatting the file, defaults to "excel"
        """
        writer = csv.writer(file, dialect=dialect)  # type: ignore
        writer.writerow(["IP", "Port", "Protocol", "State", "Service", "Reason", "Product", "Version", "CPE"])
        for host in self.hosts:
            host_info = host.address[0].addr
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
