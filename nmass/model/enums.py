from enum import Enum


class ScanType(str, Enum):
    syn = "syn"
    ack = "ack"
    bounce = "bounce"
    connect = "connect"
    null = "null"
    xmas = "xmas"
    window = "window"
    maimon = "maimon"
    fin = "fin"
    udp = "udp"
    sctpinit = "sctpinit"
    sctpcookieecho = "sctpcookieecho"
    ipproto = "ipproto"


class PortState(str, Enum):
    open = "open"
    closed = "closed"
    filtered = "filtered"
    open_or_filtered = "open|filtered"


class PortProtocol(str, Enum):
    ip = "ip"
    tcp = "tcp"
    udp = "udp"
    sctp = "sctp"


class HostState(str, Enum):
    up = "up"
    down = "down"
    unknown = "unknown"
    skipped = "skipped"


class TCPFlag(int, Enum):
    """Enum representing TCP Flags for custom scan."""

    NULL = 0
    FIN = 1
    SYN = 2
    RST = 4
    PSH = 8
    ACK = 16
    URG = 32
    ECE = 64
    CWR = 128
    NS = 256


class TimingTemplate(int, Enum):
    """Timing templates for controlling scan speed and performance.

    https://nmap.org/book/performance-timing-templates.html
    """

    Paranoid = 0
    Sneaky = 1
    Polite = 2
    Normal = 3
    Aggressive = 4
    Insane = 5
