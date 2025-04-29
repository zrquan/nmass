import asyncio
import logging
import shutil
import socket
import string
import subprocess

from pydantic import BaseModel
from typing_extensions import Self, Unpack

from .errors import MasscanExecutionError, MasscanNotInstalledError
from .model.elements import Address, NmapRun
from .scanner import ProcessArgs, Scanner
from .utils import as_root


class MasscanInfo(BaseModel):
    version: str
    compiled_time: str
    compiler: str
    os: str
    cpu: str
    git_version: str


class Masscan(Scanner):
    def __init__(self, bin_path: str = "") -> None:
        super().__init__(bin_path)

        if self.bin_path == "":
            if w := shutil.which("masscan"):
                self.bin_path = w
            else:
                raise MasscanNotInstalledError()

    @property
    def info(self) -> MasscanInfo:
        proc = subprocess.run([self.bin_path, "--version"], capture_output=True)
        info = proc.stdout.splitlines()

        def clean(line: bytes) -> str:
            return line.decode().split(":")[1].strip()

        return MasscanInfo(
            version=info[1].decode().split(" ")[2],
            compiled_time=clean(info[2]),
            compiler=clean(info[3]),
            os=clean(info[4]),
            cpu=clean(info[5]),
            git_version=clean(info[6]),
        )

    @as_root
    def run(
        self,
        timeout: float | None = None,
        **kwargs: Unpack[ProcessArgs],
    ) -> NmapRun | None:
        """Run masscan command.

        :param timeout: Timeout for masscan process, defaults to None
        :return: NmapRun object or None
        """
        try:
            return self._run_command(timeout, **kwargs)
        except subprocess.CalledProcessError as e:
            raise MasscanExecutionError(retcode=e.returncode, message=str(e))
        except subprocess.TimeoutExpired:
            logging.warning("Masscan scan timed out")
            raise

    @as_root
    async def arun(
        self,
        timeout: float | None = None,
        **kwargs: Unpack[ProcessArgs],
    ) -> NmapRun | None:
        """Run masscan command asynchronously.

        :param timeout: Timeout for masscan process, defaults to None
        :return: NmapRun object or None
        """
        try:
            return await self._arun_command(timeout, **kwargs)
        except subprocess.CalledProcessError as e:
            raise MasscanExecutionError(retcode=e.returncode, message=str(e))
        except asyncio.TimeoutError:
            logging.warning("Masscan async scan timed out")
            raise

    def with_step(self, model: NmapRun) -> Self:
        # masscan 中同一个目标会有多个 host element
        targets: set[str] = set()
        ports: set[int] = set()

        if model.hosts is None:
            raise ValueError("hosts is None")
        for host in model.hosts:
            self._process_addresses(host.address, targets)
            if host.ports is None or host.ports.ports is None:
                raise ValueError("ports is None")
            ports.update(port.portid for port in host.ports.ports)

        self.with_targets(*targets)
        self.with_ports(*ports)
        return self

    def _process_addresses(self, addresses: list[Address], targets: set[str]) -> None:
        for addr in addresses:
            if addr.addrtype == "ipv4":
                targets.add(addr.addr)
            elif addr.addrtype == "ipv6":
                logging.warning("IPv6 address is not supported in masscan")

    def with_targets(self, *targets: str) -> Self:
        """Specify the targets to be scanned.

        :param targets: There are three valid formats.
          The first is a single IPv4 address like "192.168.0.1".
          The second is a range like "10.0.0.1-10.0.0.100".
          The third is a CIDR address, like "0.0.0.0/0".
        """
        valid_characters = frozenset(string.digits + "./-")
        parsed_targets = []
        for t in targets:
            if not set(t).issubset(valid_characters):
                origin = t
                t = socket.gethostbyname(t)
                logging.warning(f"Replace {origin} with {t} (masscan doesn't like DNS name)")

            if t == "127.0.0.1":
                logging.warning("Masscan uses a custom stack. It cannot scan the local host.")
                continue

            parsed_targets.append(t)
        return super().with_targets(*parsed_targets)

    def with_rate(self, rate: int) -> Self:
        """Set the packet transmission rate (--rate).

        :param rate: Number of packets per second to send
        """
        self._args.extend(("--rate", str(rate)))
        return self

    def with_banners(self) -> Self:
        """Retrieve the banner information from scanned services (--banners)."""
        self._args.append("--banners")
        return self

    def with_config(self, filename: str) -> Self:
        """Specify a configuration file (-c, --conf).

        :param filename: Path to the configuration file
        """
        self._args.extend(("-c", filename))
        return self

    def with_resume(self, filename: str) -> Self:
        """Resume scanning from a previous configuration file (--resume).

        :param filename: Path to the resume configuration file
        """
        self._args.extend(("--resume", filename))
        return self

    # 是否要以 with_ 开头
    def echo_config(self) -> Self:
        """Echo the current configuration to a file (--echo)."""
        self._args.append("--echo")
        return self

    def with_adapter(self, interface: str) -> Self:
        """Specify the network adapter to use (-e, --adapter).

        :param interface: Network interface to use, e.g., "eth0"
        """
        self._args.extend(("-e", interface))
        return self

    def with_adapter_ip(self, ip: str) -> Self:
        """Specify the IP address of the network adapter (--adapter-ip).

        :param ip: IP address of the adapter
        """
        self._args.extend(("--adapter-ip", ip))
        return self

    def with_adapter_port(self, port: int) -> Self:
        """Specify the source port number of the network adapter (--adapter-port).

        :param port: Source port number of the adapter
        """
        self._args.extend(("--adapter-port", str(port)))
        return self

    def with_adapter_mac(self, address: str) -> Self:
        """Specify the MAC address of the network adapter (--adapter-mac).

        :param address: MAC address of the adapter
        """
        self._args.extend(("--adapter-mac", address))
        return self

    def with_router_mac(self, address: str) -> Self:
        """Specify the MAC address of the router (--router-mac).

        :param address: MAC address of the router
        """
        self._args.extend(("--router-mac", address))
        return self

    def with_ping(self) -> Self:
        """Include ICMP echo requests in the scan (--ping)."""
        self._args.append("--ping")
        return self

    def with_append_output(self) -> Self:
        """Append output to file instead of overwriting (--append-output)."""
        self._args.append("--append-output")
        return self

    # def with_iflist(self) -> Self:
    #     """List the available network interfaces and exit (--iflist)."""
    #     self._args.append("--iflist")
    #     return self

    def with_retries(self, retries: int) -> Self:
        """Set the number of retries for packet sending (--retries).

        :param retries: Number of retries
        """
        self._args.extend(("--retries", str(retries)))
        return self

    # def with_nmap_compatibility(self) -> Self:
    #     """Print help about nmap-compatibility alternatives (--nmap)."""
    #     self._args.append("--nmap")
    #     return self

    def with_pcap_payloads(self, filename: str) -> Self:
        """Read custom packet payloads from a pcap file (--pcap-payloads).

        :param filename: Path to the pcap payloads file
        """
        self._args.extend(("--pcap-payloads", filename))
        return self

    def with_nmap_payloads(self, filename: str) -> Self:
        """Read custom packet payloads from a nmap payloads file (--nmap-payloads).

        :param filename: Path to the nmap payloads file
        """
        self._args.extend(("--nmap-payloads", filename))
        return self

    def with_http_user_agent(self, user_agent: str) -> Self:
        """Specify a custom HTTP User-Agent string (--http-user-agent).

        :param user_agent: HTTP User-Agent string
        """
        self._args.extend(("--http-user-agent", user_agent))
        return self

    def without_closed_ports(self) -> Self:
        """Report only open ports, not closed ports (--open-only)."""
        self._args.append("--open-only")
        return self

    def with_pcap(self, filename: str) -> Self:
        """Save received packets to a pcap file (--pcap).

        :param filename: Path to the pcap file
        """
        self._args.extend(("--pcap", filename))
        return self

    def with_packet_trace(self) -> Self:
        """Print a summary of packets sent and received (--packet-trace)."""
        self._args.append("--packet-trace")
        return self

    def with_pfring(self) -> Self:
        """Force the use of the PF_RING driver (--pfring)."""
        self._args.append("--pfring")
        return self

    def with_resume_index(self, index: int) -> Self:
        """Set the point in the scan to resume from (--resume-index).

        :param index: Resume index
        """
        self._args.extend(("--resume-index", str(index)))
        return self

    def with_resume_count(self, count: int) -> Self:
        """Set the maximum number of probes to send before exiting (--resume-count).

        :param count: Maximum number of probes
        """
        self._args.extend(("--resume-count", str(count)))
        return self

    def with_shards(self, shard_id: int, total_shards: int) -> Self:
        """Split the scan among multiple instances (--shards).

        :param shard_id: ID of this shard
        :param total_shards: Total number of shards
        """
        self._args.extend(("--shards", f"{shard_id}/{total_shards}"))
        return self

    def with_rotate(self, time: str) -> Self:
        """Rotate the output file at specified intervals (--rotate).

        :param time: Time interval for rotation, e.g., "hourly", "10min"
        """
        self._args.extend(("--rotate", time))
        return self

    def with_rotate_offset(self, offset: str) -> Self:
        """Set an offset for the rotation interval (--rotate-offset).

        :param offset: Offset for rotation interval
        """
        self._args.extend(("--rotate-offset", offset))
        return self

    def with_rotate_dir(self, directory: str) -> Self:
        """Specify the directory to move rotated files to (--rotate-dir).

        :param directory: Directory to move rotated files to
        """
        self._args.extend(("--rotate-dir", directory))
        return self

    def with_seed(self, seed: str) -> Self:
        """Set the seed for the random number generator (--seed).

        :param seed: Seed value, or "time" for local timestamp
        """
        self._args.extend(("--seed", seed))
        return self

    def with_regress(self) -> Self:
        """Run a regression test and return '0' on success, '1' on failure (--regress)."""
        self._args.append("--regress")
        return self

    def with_ttl(self, ttl: int) -> Self:
        """Set the TTL (Time-To-Live) of outgoing packets (--ttl).

        :param ttl: TTL value
        """
        self._args.extend(("--ttl", str(ttl)))
        return self

    def with_wait(self, seconds: int) -> Self:
        """Set the number of seconds to wait after transmission is done (--wait).

        :param seconds: Number of seconds to wait, or "forever"
        """
        self._args.extend(("--wait", str(seconds)))
        return self

    def with_offline(self) -> Self:
        """Do not actually transmit packets, useful for benchmarking (--offline)."""
        self._args.append("--offline")
        return self

    def with_sL(self) -> Self:
        """Create a list of random addresses without scanning (-sL)."""
        self._args.append("-sL")
        return self
