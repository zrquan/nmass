import asyncio
import logging
import shutil
import subprocess
from dataclasses import dataclass
from typing import Self

from nmass.errors import MasscanExecutionError, MasscanNotInstalledError
from nmass.models import NmapRun
from nmass.scanner import Scanner
from nmass.utils import as_root


@dataclass
class Masscan(Scanner):
    def __post_init__(self):
        """Initialize Masscan instance and verify if masscan is installed."""
        if self.bin_path == "":
            if w := shutil.which("masscan"):
                self.bin_path = w
            else:
                raise MasscanNotInstalledError()

    @as_root
    def run(
        self,
        timeout: float | None = None,
        with_output: bool = False,
    ) -> NmapRun | None:
        """Run masscan command.

        :param timeout: Timeout for masscan process, defaults to None
        :param with_output: Print masscan's output, defaults to False
        :return: NmapRun object or None
        """
        try:
            return self._run_command(timeout, with_output)
        except subprocess.CalledProcessError as e:
            raise MasscanExecutionError(retcode=e.returncode)
        except subprocess.TimeoutExpired:
            logging.warn("masscan scanning timeout")
            raise

    @as_root
    async def arun(
        self,
        timeout: float | None = None,
        # FIXME: 异步执行 masscan 时，没有输出进度和倒计时那一行
        with_output: bool = False,
    ) -> NmapRun | None:
        """Run masscan command asynchronously.

        :param timeout: Timeout for masscan process, defaults to None
        :param with_output: Print masscan's output, defaults to False
        :return: NmapRun object or None
        """
        try:
            return await self._arun_command(timeout, with_output)
        except subprocess.CalledProcessError as e:
            raise MasscanExecutionError(retcode=e.returncode)
        except asyncio.TimeoutError:
            logging.warn("asynchronous masscan scanning timeout")
            raise

    def with_rate(self, rate: int) -> Self:
        """Set the packet transmission rate (--rate).

        :param rate: Number of packets per second to send
        """
        self._args.extend(("--rate", str(rate)))
        return self

    def with_banner(self) -> Self:
        """Retrieve the banner information from scanned services (--banner)."""
        self._args.append("--banner")
        return self

    def with_config(self, filename: str) -> Self:
        """Specify a configuration file (-c).

        :param filename: Path to the configuration file
        """
        self._args.extend(("-c", filename))
        return self

    # 是否要以 with_ 开头
    def echo_config(self) -> Self:
        """Echo the current configuration (--echo)."""
        self._args.append("--echo")
        return self

    def with_adapter_ip(self, ip: str) -> Self:
        """Specify the IP address of the network adapter (--adapter-ip).

        :param ip: IP address of the adapter
        """
        self._args.extend(("--adapter-ip", ip))
        return self

    def with_adapter_port(self, port: int) -> Self:
        """Specify the port number of the network adapter (--adapter-port).

        :param port: Port number of the adapter
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

    def with_retries(self, retries: int) -> Self:
        """Set the number of retries for packet sending (--retries).

        :param retries: Number of retries
        """
        self._args.extend(("--retries", str(retries)))
        return self

    def with_pcap_payloads(self, filename: str) -> Self:
        """Specify a file containing custom packet payloads in pcap format (--pcap-payloads).

        :param filename: Path to the pcap payloads file
        """
        self._args.extend(("--pcap-payloads", filename))
        return self

    def with_nmap_payloads(self, filename: str) -> Self:
        """Specify a file containing custom packet payloads in nmap format (--nmap-payloads).

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
        """Only show open ports (--open-only)."""
        self._args.append("--open-only")
        return self
