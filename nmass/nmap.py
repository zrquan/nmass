import asyncio
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Literal, Optional

from typing_extensions import Self

from nmass.errors import NmapArgumentError, NmapExecutionError, NmapNotInstalledError
from nmass.model.elements import Address, NmapRun
from nmass.model.enums import TCPFlag, TimingTemplate
from nmass.scanner import Scanner
from nmass.utils import as_root


class Nmap(Scanner):
    def __init__(self, bin_path: str = "") -> None:
        super().__init__(bin_path)

        if self.bin_path == "" or not Path(self.bin_path).is_file():
            if w := shutil.which("nmap"):
                self.bin_path = w
            else:
                raise NmapNotInstalledError()

    def run(
        self,
        timeout: Optional[float] = None,
        with_output: bool = False,
    ) -> Optional[NmapRun]:
        """Run nmap command.

        :param timeout: Timeout for nmap process, defaults to None
        :param with_output: Print nmap's output, defaults to False
        :return: NmapRun object or None
        """
        try:
            return self._run_command(timeout, with_output)
        except subprocess.CalledProcessError as e:
            raise NmapExecutionError(retcode=e.returncode, message=str(e.stderr))
        except subprocess.TimeoutExpired:
            logging.warn("nmap scanning timeout")
            raise

    async def arun(
        self,
        timeout: Optional[float] = None,
        with_output: bool = False,
    ) -> Optional[NmapRun]:
        """Run nmap command asynchronously.

        :param timeout: Timeout for nmap process, defaults to None
        :param with_output: Print nmap's output, defaults to False
        :return: NmapRun object or None
        """
        try:
            return await self._arun_command(timeout, with_output)
        except subprocess.CalledProcessError as e:
            raise NmapExecutionError(retcode=e.returncode, message=str(e))
        except asyncio.TimeoutError:
            logging.warn("asynchronous nmap scanning timeout")
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
                self.with_ipv6()
                targets.add(addr.addr)

    ### TARGET SPECIFICATION ###

    def with_random_targets(self, number: int) -> Self:
        """Choose random targets for scanning.

        :param number: Number of IPs to generate for scanning
        """
        self._args.extend(("-iR", str(number)))
        return self

    ### HOST DISCOVERY ###

    def with_list_scan(self) -> Self:
        """List Scan (-sL): Simply list targets to scan."""
        self._args.append("-sL")
        return self

    def with_ping_scan(self) -> Self:
        """Ping Scan (-sn): Disable port scan, only discover hosts."""
        self._args.append("-sn")
        return self

    def without_ping(self) -> Self:
        """Treat all hosts as online -- skip host discovery (-Pn)."""
        self._args.append("-Pn")
        return self

    # TODO: -PS/PA/PU/PY 应该只能选其一

    def with_syn_discovery(self, *ports: str) -> Self:
        """TCP SYN Discovery (-PS): Send SYN packets to specified ports.

        :param ports: Ports to perform SYN discovery on
        """
        ports_str = ",".join(ports)
        self._args.append(f"-PS{ports_str}")
        return self

    def with_ack_discovery(self, *ports: str) -> Self:
        """TCP ACK Discovery (-PA): Send ACK packets to specified ports.

        :param ports: Ports to perform ACK discovery on
        """
        ports_str = ",".join(ports)
        self._args.append(f"-PA{ports_str}")
        return self

    def with_udp_discovery(self, *ports: str) -> Self:
        """UDP Discovery (-PU): Send UDP packets to specified ports.

        :param ports: Ports to perform UDP discovery on
        """
        ports_str = ",".join(ports)
        self._args.append(f"-PU{ports_str}")
        return self

    def with_sctp_discovery(self, *ports: str) -> Self:
        """SCTP INIT Discovery (-PY): Send SCTP INIT packets to specified ports.

        :param ports: Ports to perform SCTP discovery on
        """
        ports_str = ",".join(ports)
        self._args.append(f"-PY{ports_str}")
        return self

    # TODO: -PE/PP/PM 应该只能选其一

    def with_icmp_echo_discovery(self) -> Self:
        """ICMP Echo Request Discovery (-PE): Send ICMP Echo Request packets."""
        self._args.append("-PE")
        return self

    def with_icmp_timestamp_discovery(self) -> Self:
        """ICMP Timestamp Request Discovery (-PP): Send ICMP Timestamp Request packets."""
        self._args.append("-PP")
        return self

    def with_icmp_netmask_discovery(self) -> Self:
        """ICMP Netmask Request Discovery (-PM): Send ICMP Netmask Request packets."""
        self._args.append("-PM")
        return self

    def with_ip_protocol_ping_discovery(self, *protocols: str) -> Self:
        """IP Protocol Ping Discovery (-PO): Send packets for specified protocols.

        :param protocols: Protocols to use for IP ping discovery
        """
        protocols_str = ",".join(protocols)
        self._args.append(f"-PO{protocols_str}")
        return self

    # TODO: -n/R 应该只能选其一

    def without_dns_resolution(self) -> Self:
        """Skip DNS resolution (-n)."""
        self._args.append("-n")
        return self

    def with_forced_dns_resolution(self) -> Self:
        """Force DNS resolution of all targets (-R)."""
        self._args.append("-R")
        return self

    def with_custom_dns_servers(self, *servers: str) -> Self:
        """Specify custom DNS servers (--dns-servers).

        :param servers: List of DNS servers to use
        """
        servers_str = ",".join(servers)
        self._args.extend(("--dns-servers", servers_str))
        return self

    def with_system_dns(self) -> Self:
        """Use OS's DNS resolver (--system-dns)."""
        self._args.append("--system-dns")
        return self

    def with_traceroute(self) -> Self:
        """Perform traceroute to discovered hosts (--traceroute)."""
        self._args.append("--traceroute")
        return self

    ### SCAN TECHNIQUES ###

    @as_root
    def with_syn_scan(self) -> Self:
        """TCP SYN Scan (-sS)."""
        self._args.append("-sS")
        return self

    def with_connect_scan(self) -> Self:
        """TCP Connect Scan (-sT)."""
        self._args.append("-sT")
        return self

    def with_ack_scan(self) -> Self:
        """TCP ACK Scan (-sA)."""
        self._args.append("-sA")
        return self

    def with_window_scan(self) -> Self:
        """TCP Window Scan (-sW)."""
        self._args.append("-sW")
        return self

    def with_maimon_scan(self) -> Self:
        """TCP Maimon Scan (-sM)."""
        self._args.append("-sM")
        return self

    def with_udp_scan(self) -> Self:
        """UDP Scan (-sU)."""
        self._args.append("-sU")
        return self

    def with_tcp_null_scan(self) -> Self:
        """TCP Null Scan (-sN)."""
        self._args.append("-sN")
        return self

    def with_tcp_fin_scan(self) -> Self:
        """TCP FIN Scan (-sF)."""
        self._args.append("-sF")
        return self

    def with_tcp_xmas_scan(self) -> Self:
        """TCP Xmas Scan (-sX)."""
        self._args.append("-sX")
        return self

    # TODO: https://nmap.org/book/scan-methods-custom-scanflags.html
    def with_tcp_scan_flags(self, *flags: TCPFlag) -> Self:
        """Custom TCP Scan Flags (--scanflags).

        :param flags: List of TCP flags to set
        """
        total = 0
        for f in flags:
            total += int(f)

        self._args.extend(("--scanflags", str(total)))
        return self

    def with_idle_scan(self, zombie_host: str, probe_port: int) -> Self:
        """Idle Scan using a zombie host (-sI).

        :param zombie_host: IP address of the zombie host
        :param probe_port: Probe port number
        """
        self._args.append("-sI")
        if probe_port > 0:
            self._args.append(f"{zombie_host}:{probe_port}")
        else:
            self._args.append(zombie_host)
        return self

    def with_sctp_init_scan(self) -> Self:
        """SCTP INIT Scan (-sY)."""
        self._args.append("-sY")
        return self

    def with_sctp_cookie_echo_scan(self) -> Self:
        """SCTP COOKIE-ECHO Scan (-sZ)."""
        self._args.append("-sZ")
        return self

    def with_ip_protocol_scan(self) -> Self:
        """IP Protocol Scan (-sO)."""
        self._args.append("-sO")
        return self

    def with_ftp_bounce_scan(self, ftp_relay_host: str) -> Self:
        """FTP Bounce Scan (-b) using a relay host.

        :param ftp_relay_host: IP address of the FTP relay host
        """
        self._args.extend(("-b", ftp_relay_host))
        return self

    ### PORT SPECIFICATION AND SCAN ORDER ###

    def with_port_exclusion(self, *ports: str) -> Self:
        """Exclude specified ports from scanning (--exclude-ports).

        :param ports: List of ports to exclude
        """
        ports_str = ",".join(ports)
        self._args.extend(("--exclude-ports", ports_str))
        return self

    def with_fast_mode(self) -> Self:
        """Enable fast mode (-F), scans fewer ports than the default scan."""
        self._args.append("-F")
        return self

    def with_consecutive_port_scanning(self) -> Self:
        """Scan ports sequentially (-r), do not randomize the order."""
        self._args.append("-r")
        return self

    def with_most_common_ports(self, top: int) -> Self:
        """Scan the most common ports (--top-ports).

        :param top: Number of top common ports to scan
        :raises NmapArgumentError: If top is not between 1 and 65535
        """
        if not 0 < top <= 65535:
            raise NmapArgumentError(
                f"invalid argument value {top=}, port number should between 1 to 65535",
                nmap_arg="--top-ports",
            )
        self._args.extend(("--top-ports", str(top)))
        return self

    def with_port_ratio(self, ratio: float) -> Self:
        """Scan ports more common than a specified ratio (--port-ratio).

        :param ratio: Ratio for common ports
        :raises NmapArgumentError: If ratio is not between 0 and 1
        """
        if not 0 < ratio < 1:
            raise NmapArgumentError(
                f"invalid argument value {ratio=}, should be between 0 to 1",
                nmap_arg="--port-ratio",
            )
        self._args.extend(("--port-ratio", str(ratio)))
        return self

    ### SERVICE/VERSION DETECTION ###

    def with_service_info(self) -> Self:
        """Detect service versions (-sV)."""
        self._args.append("-sV")
        return self

    def with_version_intensity(self, intensity: int = 7) -> Self:
        """Set version scan intensity (--version-intensity).

        :param intensity: Intensity level (0 to 9)
        :raises NmapArgumentError: If intensity is not between 0 and 9
        """
        if not 0 <= intensity <= 9:
            raise NmapArgumentError(
                f"invalid argument value {intensity=}, please set from 0 (light) to 9 (try all probes)",
                nmap_arg="--version-intensity",
            )
        self._args.extend(("--version-intensity", str(intensity)))
        return self

    def with_version_light(self) -> Self:
        """Limit version scan to most likely probes (--version-light, intensity 2)."""
        self._args.append("--version-light")
        return self

    def with_version_all(self) -> Self:
        """Try every single probe (--version-all, intensity 9)."""
        self._args.append("--version-all")
        return self

    def with_version_trace(self) -> Self:
        """Show detailed version scan activity (--version-trace, for debugging)."""
        self._args.append("--version-trace")
        return self

    ### SCRIPT SCAN ###

    def with_default_script(self) -> Self:
        """Run default script scan (-sC)."""
        self._args.append("-sC")
        return self

    def with_scripts(self, *scripts: str) -> Self:
        """Run specified scripts (--script).

        :param scripts: List of scripts to run
        """
        scripts_str = ",".join(scripts)
        self._args.append(f"--script={scripts_str}")
        return self

    def with_script_arguments(self, **arguments: str) -> Self:
        """Pass arguments to scripts (--script-args).

        :param arguments: Dictionary of script arguments
        """
        script_args = "--script-args="
        for k, v in arguments.items():
            if not v:
                script_args += f"{k},"
            else:
                script_args += f"{k}={v},"
        self._args.append(script_args[:-1])
        return self

    def with_script_arguments_file(self, filename: str) -> Self:
        """Load script arguments from a file (--script-args-file).

        :param filename: File containing script arguments
        """
        self._args.append(f"--script-args-file={filename}")
        return self

    def with_script_trace(self) -> Self:
        """Show all data sent and received during script scan (--script-trace)."""
        self._args.append("--script-trace")
        return self

    def with_script_update_db(self) -> Self:
        """Update the script database (--script-updatedb)."""
        self._args.append("--script-updatedb")
        return self

    def with_script_help(self, *scripts: str) -> Self:
        """Show help for specified scripts (--script-help).

        :param scripts: List of scripts to show help for
        """
        scripts_str = ",".join(scripts)
        self._args.append(f"--script-help={scripts_str}")
        return self

    ### OS DETECTION ###

    @as_root
    def with_os_detection(self) -> Self:
        """Enable OS detection (-O)."""
        self._args.append("-O")
        return self

    @as_root
    def with_osscan_limit(self) -> Self:
        """Limit OS detection to promising targets (--osscan-limit)."""
        self._args.append("--osscan-limit")
        return self

    @as_root
    def with_osscan_guess(self) -> Self:
        """Guess OS when detection is not conclusive (--osscan-guess)."""
        self._args.append("--osscan-guess")
        return self

    ### TIMING AND PERFORMANCE ###

    def with_timing_template(self, template: TimingTemplate) -> Self:
        """Set timing template (-T).

        :param template: Timing template to use
        """
        self._args.append(f"-T{int(template)}")
        return self

    def with_hostgroup_size(
        self,
        min: Optional[int] = None,
        max: Optional[int] = None,
    ) -> Self:
        """Parallel host scan group sizes (--min-hostgroup, --max-hostgroup).

        :param min: Minimum host group size, defaults to None
        :param max: Maximum host group size, defaults to None
        :raises NmapArgumentError: If both min and max are None
        """
        if not (min or max):
            raise NmapArgumentError("please provide at least one argument", nmap_arg="hostgroup")
        if min:
            self._args.extend(("--min-hostgroup", str(min)))
        if max:
            self._args.extend(("--max-hostgroup", str(max)))
        return self

    def with_parallelism(
        self,
        min: Optional[int] = None,
        max: Optional[int] = None,
    ) -> Self:
        """Probe parallelization (--min-parallelism, --max-parallelism).

        :param min: Minimum parallelism, defaults to None
        :param max: Maximum parallelism, defaults to None
        :raises NmapArgumentError: If both min and max are None
        """
        if not (min or max):
            raise NmapArgumentError(
                "please provide at least one argument",
                nmap_arg="parallelism",
            )
        if min:
            self._args.extend(("--min-parallelism", str(min)))
        if max:
            self._args.extend(("--max-parallelism", str(max)))
        return self

    def with_rtt_timeout(
        self,
        min: Optional[int] = None,
        max: Optional[int] = None,
        initial: Optional[int] = None,
    ) -> Self:
        """Specifies probe round trip time (--min-rtt-timeout, --max-rtt-timeout, --initial-rtt-timeout).

        :param min: Minimum RTT timeout, defaults to None
        :param max: Maximum RTT timeout, defaults to None
        :param initial: Initial RTT timeout, defaults to None
        :raises NmapArgumentError: If all parameters are None
        """
        if not (min or max or initial):
            raise NmapArgumentError("please provide at least one argument", nmap_arg="rtt-timeout")
        if min:
            self._args.extend(("--min-rtt-timeout", str(min)))
        if max:
            self._args.extend(("--max-rtt-timeout", str(max)))
        if initial:
            self._args.extend(("--initial-rtt-timeout", str(initial)))
        return self

    def with_max_retries(self, tries: int) -> Self:
        """Caps number of port scan probe retransmissions (--max-retries).

        :param tries: Maximum number of retries
        """
        self._args.extend(("--max-retries", str(tries)))
        return self

    def with_host_timeout(self, timeout: int) -> Self:
        """Give up on target after this long (--host-timeout).

        :param timeout: Host timeout in milliseconds
        """
        self._args.extend(("--host-timeout", str(timeout)))
        return self

    def with_scan_delay(
        self,
        time: Optional[int] = None,
        max_time: Optional[int] = None,
    ) -> Self:
        """Adjust delay between probes (--scan-delay, --max-scan-delay).

        :param time: Scan delay time, defaults to None
        :param max_time: Maximum scan delay time, defaults to None
        :raises NmapArgumentError: If both time and max_time are None
        """
        if not (time or max_time):
            raise NmapArgumentError("please provide at least one argument", nmap_arg="scan-delay")
        if time:
            self._args.extend(("--scan-delay", str(time)))
        if max_time:
            self._args.extend(("--max-scan-delay", str(max_time)))
        return self

    def with_rate(
        self,
        min: Optional[int] = None,
        max: Optional[int] = None,
    ) -> Self:
        """Send packets no slower/faster than min/max per second (--min-rate, --max-rate).

        :param min: Minimum rate, defaults to None
        :param max: Maximum rate, defaults to None
        :raises NmapArgumentError: If both min and max are None
        """
        if not (min or max):
            raise NmapArgumentError("please provide at least one argument", nmap_arg="rate")
        if min:
            self._args.extend(("--min-rate", str(min)))
        if max:
            self._args.extend(("--max-rate", str(max)))
        return self

    ### FIREWALL/IDS EVASION AND SPOOFING ###

    # TODO: 可以重复使用 -f 来继续减少切片的数量？（大小？）
    def with_fragment_packets(self) -> Self:
        """Fragment packets to evade firewall/IDS (-f)."""
        self._args.append("-f")
        return self

    def with_mtu(self, offset: int) -> Self:
        """Specify MTU (Maximum Transmission Unit) offset (--mtu).

        :param offset: MTU offset, must be a multiple of eight
        :raises NmapArgumentError: If offset is not a multiple of eight
        """
        if offset % 8 != 0:
            raise NmapArgumentError(
                f"invalid argument value {offset=}, the offset must be a multiple of eight",
                nmap_arg="--mtu",
            )
        self._args.extend(("--mtu", str(offset)))
        return self

    def with_decoys(self, *decoys: str) -> Self:
        """Use decoys to obfuscate scan origin (-D).

        :param decoys: List of decoy IP addresses
        """
        decoys_str = ",".join(decoys)
        self._args.extend(("-D", decoys_str))
        return self

    def with_spoof_address(self, ip: str) -> Self:
        """Spoof source IP address (-S).

        :param ip: IP address to spoof
        """
        self._args.extend(("-S", ip))
        return self

    def with_interface(self, iface: str) -> Self:
        """Specify network interface to use (-e).

        :param iface: Network interface name
        """
        self._args.extend(("-e", iface))
        return self

    def with_source_port(self, port: int) -> Self:
        """Specify source port number (--source-port).

        :param port: Source port number
        """
        self._args.extend(("--source-port", str(port)))
        return self

    def with_proxies(self, *proxies: str) -> Self:
        """Use specified proxies for scanning (--proxies).

        :param proxies: List of proxy addresses
        """
        proxies_str = ",".join(proxies)
        self._args.extend(("--proxies", proxies_str))
        return self

    def with_hex_data(self, data: str) -> Self:
        """Send specified hex data (--data).

        :param data: Hex data string
        """
        self._args.extend(("--data", data))
        return self

    def with_ascii_data(self, data: str) -> Self:
        """Send specified ASCII data (--data-string).

        :param data: ASCII data string
        """
        self._args.extend(("--data-string", data))
        return self

    def with_data_length(self, length: int) -> Self:
        """Append random data to sent packets (--data-length).

        :param length: Length of random data
        """
        self._args.extend(("--data-length", str(length)))
        return self

    def with_ip_options(self, options: str) -> Self:
        """Send specified IP options (--ip-options).

        :param options: IP options string
        """
        self._args.extend(("--ip-options", options))
        return self

    def with_time_to_live(self, ttl: int) -> Self:
        """Set IP time-to-live (TTL) field (-ttl).

        :param ttl: TTL value
        :raises NmapArgumentError: If TTL is not between 0 and 225
        """
        if not 0 < ttl < 225:
            raise NmapArgumentError(
                f"invalid argument value {ttl=}, should be between 0 to 225",
                nmap_arg="-ttl",
            )
        self._args.extend(("-ttl", str(ttl)))
        return self

    def with_spoof_mac(self, mac: str) -> Self:
        """Spoof MAC address (--spoof-mac).

        :param mac: MAC address to spoof
        """
        self._args.extend(("--spoof-mac", mac))
        return self

    def with_bad_sum(self) -> Self:
        """Send packets with a bogus TCP/UDP/SCTP checksum (--badsum)."""
        self._args.append("--badsum")
        return self

    ### OUTPUT ###

    def with_output_file(
        self,
        filename: str,
        format: Literal["N", "X", "S", "G", "A"] = "N",
    ) -> Self:
        """Output scan in specified format (-oN, -oX, -oS, -oG, -oA).

        :param filename: Name of output file
        :param format:
          - N for normal
          - X for XML
          - S for s|<rIpt
          - G for kIddi3
          - A means output in the three major formats at once
        """
        self._args.extend((f"-o{format}", filename))
        return self

    def with_verbose(self, level: int = 1) -> Self:
        """Increase verbosity level (-v, -vv, ...).

        :param level: Verbosity level
        """
        self._args.append("-" + "v" * level)
        return self

    def with_debugging(self, level: int = 1) -> Self:
        """Increase debugging level (-d, -dd, ...).

        :param level: Debugging level
        """
        self._args.append("-" + "d" * level)
        return self

    def with_reason(self) -> Self:
        """Display the reason a port is in a particular state (--reason)."""
        self._args.append("--reason")
        return self

    def without_closed_ports(self) -> Self:
        """Only show open (or possibly open) ports (--open)."""
        self._args.append("--open")
        return self

    def with_packet_trace(self) -> Self:
        """Show all packets sent and received (--packet-trace)."""
        self._args.append("--packet-trace")
        return self

    # TODO:
    # --iflist: Print host interfaces and routes (for debugging)
    # --append-output: Append to rather than clobber specified output files
    # --resume <filename>: Resume an aborted scan
    # --noninteractive: Disable runtime interactions via keyboard
    # --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
    # --webxml: Reference stylesheet from Nmap.Org for more portable XML
    # --no-stylesheet: Prevent associating of XSL stylesheet w/XML output

    ### MISC ###
    # ignore: -V: Print version number
    # ignore: -h: Print this help summary page

    def with_ipv6(self) -> Self:
        """Scan targets using IPv6 (-6)."""
        self._args.append("-6")
        return self

    @as_root
    def with_aggressive_scan(self) -> Self:
        """Enable aggressive scan options (-A)."""
        self._args.append("-A")
        return self

    def with_data_dir(self, dirname: str) -> Self:
        """Specify custom data directory (--datadir).

        :param dirname: Path to data directory
        """
        self._args.extend(("--datadir", dirname))
        return self

    def with_send_ethernet(self) -> Self:
        """Send packets at raw ethernet level (--send-eth)."""
        self._args.append("--send-eth")
        return self

    def with_send_ip(self) -> Self:
        """Send packets at raw IP level (--send-ip)."""
        self._args.append("--send-ip")
        return self

    def with_privileged(self) -> Self:
        """Assume that the user has special privileges (--privileged)."""
        self._args.append("--privileged")
        return self

    def without_privileged(self) -> Self:
        """Assume that the user does not have special privileges (--unprivileged)."""
        self._args.append("--unprivileged")
        return self
