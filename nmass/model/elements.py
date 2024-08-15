from typing import Literal

from pydantic_xml import BaseXmlModel, RootXmlModel, attr, element

from nmass.model.enums import HostState, PortProtocol, PortState, ScanType


class CPE(RootXmlModel[str]):
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
    numservices: int | None = attr(default=None)
    services: str | None = attr(default=None)


class Service(BaseXmlModel, tag="service"):
    name: str = attr()
    banner: str | None = attr(default=None)  # for masscan
    product: str | None = attr(default=None)
    version: str | None = attr(default=None)
    method: Literal["table", "probed"] | None = attr(default=None)
    confidence: int | None = attr(name="conf", default=None)
    cpe: CPE | None = element(default=None)


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
    service: Service | None = element(default=None)
    scripts: list[Script] | None = element(default=None)


class PortUsed(BaseXmlModel, tag="portused"):
    state: PortState = attr()
    proto: PortProtocol = attr()
    portid: int = attr()


class Ports(BaseXmlModel, tag="ports"):
    extraports: dict[str, str] | None = element(default=None)
    ports: list[Port] | None = element(default=None)


class Hostname(BaseXmlModel, tag="hostname"):
    name: str = attr()
    type: Literal["user", "PTR"] = attr()


class Hostnames(BaseXmlModel, tag="hostnames"):
    hostnames: list[Hostname] | None = element(default=None)


class OSClass(BaseXmlModel, tag="osclass"):
    type: str = attr()
    vendor: str = attr()
    osfamily: str = attr()
    osgen: str = attr()
    accuracy: int = attr()
    cpe: CPE | None = element(default=None)


class OSMatch(BaseXmlModel, tag="osmatch"):
    name: str = attr()
    accuracy: int = attr()
    line: int = attr()
    osclasses: list[OSClass]


class OS(BaseXmlModel, tag="os"):
    used_ports: list[PortUsed] | None = element(default=None)
    osmatches: list[OSMatch] | None = element(default=None)


class Trace(BaseXmlModel, tag="trace"):
    pass


class Address(BaseXmlModel, tag="address"):
    addr: str = attr()
    addrtype: Literal["ipv4", "ipv6", "mac"] = attr()


class Host(BaseXmlModel, tag="host"):
    class Status(BaseXmlModel, tag="status"):
        state: HostState = attr()
        reason: str = attr()
        reason_ttl: str | None = attr(default=None)

    status: Status | None = element(default=None)  # None for masscan
    address: list[Address]
    hostnames: Hostnames | None = element(default=None)
    ports: Ports | None = element(default=None)
    os: OS | None = element(default=None)
    uptime: dict[str, str] | None = element(default=None)
    distance: dict[str, int] | None = element(default=None)
    tcpsequence: dict[str, str] | None = element(default=None)
    ipidsequence: dict[str, str] | None = element(default=None)
    tcptssequence: dict[str, str] | None = element(default=None)
    trace: Trace | None = element(default=None)
    times: dict[str, int] | None = element(default=None)


class HostHint(BaseXmlModel, tag="hosthint"):
    status: Host.Status = element()
    address: list[Address]
    hostnames: Hostnames | None = element(default=None)


class TaskProgress(BaseXmlModel, tag="taskprogress"):
    task: str = attr()
    time: str = attr()
    percent: float = attr()
    remaining: int | None = attr(default=None)
    etc: str | None = attr(default=None)


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
    start_time: str | None = attr(name="startstr", default=None)
    version: str = attr()
    xmloutputversion: str = attr()

    # https://seclists.org/nmap-dev/2005/q1/77
    scaninfo: ScanInfo | None = element(default=None)
    verbose: dict[str, int] | None = element(default=None)  # None for masscan
    debugging: dict[str, int] | None = element(default=None)  # None for masscan
    hosthint: HostHint | None = element(default=None)
    taskprogress: list[TaskProgress] | None = element(default=None)
    hosts: list[Host] | None = element(default=None)
    stats: Stats | None = element(default=None)
