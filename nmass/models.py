from typing import Literal

from pydantic_xml import BaseXmlModel, attr, element

# TODO: 完善数据模型，等完全覆盖 Nmap XML 之后可使用默认 strict 模式
# https://nmap.org/book/nmap-dtd.html
# https://pydantic-xml.readthedocs.io/en/latest/pages/data-binding/elements.html#elements-search-mode
MODE = "ordered"


class ScanInfo(BaseXmlModel, tag="scaninfo"):
    # TODO: (syn|ack|bounce|connect|null|xmas|window|maimon|fin|udp|sctpinit|sctpcookieecho|ipproto)
    type: str = attr()
    protocol: Literal["ip", "tcp", "udp", "sctp"] = attr()
    numservices: int = attr(default=None)
    services: str = attr(default=None)


class Service(BaseXmlModel, tag="service"):
    name: str = attr()
    banner: str = attr(default=None)  # for masscan
    product: str = attr(default=None)
    version: str = attr(default=None)
    method: Literal["table", "probed"] = attr(default=None)
    confidence: int = attr(name="conf", default=None)
    cpe: str = element(default=None)


class Script(BaseXmlModel, tag="script"):
    id: str = attr()
    output: str = attr()


class Port(BaseXmlModel, tag="port"):
    class State(BaseXmlModel, tag="state"):
        state: Literal["open", "closed", "filtered"] = attr()
        reason: str = attr()
        reason_ttl: str = attr()

    protocol: Literal["ip", "tcp", "udp", "sctp"] = attr()
    portid: int = attr()
    state: State
    service: Service = element(default=None)
    scripts: list[Script] = element(default=None)


class PortUsed(BaseXmlModel, tag="portused"):
    state: Literal["open", "closed", "filtered"] = attr()
    proto: Literal["ip", "tcp", "udp", "sctp"] = attr()
    portid: int = attr()


class Ports(BaseXmlModel, tag="ports"):
    extraports: dict[str, str] = element(default=None)
    ports: list[Port] = element()


class Hostname(BaseXmlModel, tag="hostname"):
    name: str = attr()
    type: Literal["user", "PTR"] = attr()


class Hostnames(BaseXmlModel, tag="hostnames"):
    hostnames: list[Hostname] = element(default=None)


class OSClass(BaseXmlModel, tag="osclass"):
    type: str = attr()
    vendor: str = attr()
    osfamily: str = attr()
    osgen: str = attr()
    accuracy: int = attr()
    cpe: str = element(default=None)


class OSMatch(BaseXmlModel, tag="osmatch"):
    name: str = attr()
    accuracy: int = attr()
    line: int = attr()
    osclasses: list[OSClass]


class OS(BaseXmlModel, tag="os"):
    used_ports: list[PortUsed]
    osmatches: list[OSMatch]


class Trace(BaseXmlModel, tag="trace"):
    pass


class Address(BaseXmlModel, tag="address"):
    addr: str = attr()
    addrtype: Literal["ipv4", "ipv6", "mac"] = attr()


class Host(BaseXmlModel, tag="host"):
    class Status(BaseXmlModel, tag="status"):
        state: Literal["up", "down", "unknown", "skipped"] = attr()
        reason: str = attr()
        reason_ttl: str = attr()

    status: Status = element(default=None)  # None for masscan
    address: list[Address]
    hostnames: Hostnames = element(default=None)
    ports: Ports
    os: OS = element(default=None)
    uptime: dict[str, str] = element(default=None)
    distance: dict[str, int] = element(default=None)
    tcpsequence: dict[str, str] = element(default=None)
    ipidsequence: dict[str, str] = element(default=None)
    tcptssequence: dict[str, str] = element(default=None)
    trace: Trace = element(default=None)
    times: dict[str, int] = element(default=None)


class HostHint(BaseXmlModel, tag="hosthint"):
    status: Host.Status = element()
    address: list[Address]
    hostnames: Hostnames = element(default=None)


class NmapRun(BaseXmlModel, tag="nmaprun", search_mode=MODE):
    """
    This is the data model that maps with the Nmap (also Masscan) XML output.
    Refer to https://nmap.org/book/nmap-dtd.html for details.
    """

    class Stats(BaseXmlModel, tag="runstats"):
        finished: dict[str, str] = element()
        hosts: dict[str, int] = element()

    scanner: Literal["nmap", "masscan"] = attr()
    args: str = attr(default=None)
    start: int = attr(default=None)
    start_time: str = attr(name="startstr", default=None)
    version: str = attr()
    xmloutputversion: str = attr()

    scaninfo: ScanInfo
    verbose: dict[str, int] = element(default=None)  # None for masscan
    debugging: dict[str, int] = element(default=None)  # None for masscan
    hosthint: HostHint = element(default=None)
    hosts: list[Host]
    stats: Stats
