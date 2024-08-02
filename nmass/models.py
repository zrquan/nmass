from typing import Literal

from pydantic_xml import BaseXmlModel, attr, element

# TODO: 完善数据模型，等完全覆盖 Nmap XML 之后可使用默认 strict 模式
# https://nmap.org/book/nmap-dtd.html
# https://pydantic-xml.readthedocs.io/en/latest/pages/data-binding/elements.html#elements-search-mode
MODE = "ordered"


class ScanInfo(BaseXmlModel, tag="scaninfo"):
    type: str = attr()
    protocol: str = attr()
    numservices: str = attr(default=None)
    services: str = attr(default=None)


class Service(BaseXmlModel, tag="service"):
    name: str = attr()
    banner: str = attr(default=None)  # masscan
    product: str = attr(default=None)
    version: str = attr(default=None)
    method: str = attr(default=None)
    confidence: str = attr(name="conf", default=None)
    cpe: str = element(default=None)


class Script(BaseXmlModel, tag="script"):
    id: str = attr()
    output: str = attr()


class Port(BaseXmlModel, tag="port"):
    class State(BaseXmlModel, tag="state"):
        state: Literal["open", "closed", "filtered"] = attr()
        reason: str = attr()
        reason_ttl: str = attr()

    protocol: str = attr()
    portid: int = attr()
    state: State
    service: Service = element(default=None)
    scripts: list[Script] = element(default=None)


class Ports(BaseXmlModel, tag="ports"):
    extraports: dict[str, str] = element(default=None)
    ports: list[Port] = element()


class Hostname(BaseXmlModel, tag="hostname"):
    name: str = attr()
    type: str = attr()


class Hostnames(BaseXmlModel, tag="hostnames"):
    hostnames: list[Hostname] = element(default=None)


class OS(BaseXmlModel, tag="os"):
    pass


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

    status: Status = element(default=None)
    address: list[Address]
    hostnames: Hostnames = element(default=None)
    ports: Ports
    os: OS = element(default=None)
    uptime: dict[str, str] = element(default=None)
    distance: dict[str, str] = element(default=None)
    tcpsequence: dict[str, str] = element(default=None)
    ipidsequence: dict[str, str] = element(default=None)
    tcptssequence: dict[str, str] = element(default=None)
    trace: Trace = element(default=None)
    times: dict[str, str] = element(default=None)


class NmapRun(BaseXmlModel, tag="nmaprun", search_mode=MODE):
    class Stats(BaseXmlModel, tag="runstats"):
        finished: dict[str, str] = element()
        hosts: dict[str, str] = element()

    scanner: str = attr()
    args: str = attr(default=None)
    start: str = attr()
    start_time: str = attr(name="startstr", default=None)
    version: str = attr()
    xmloutputversion: str = attr()

    scaninfo: ScanInfo
    # verbose: dict[str, str] = element()
    # debugging: dict[str, str] = element()
    # hosthint: HostHint
    hosts: list[Host]
    stats: Stats
