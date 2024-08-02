import enum
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Self

from nmass.errors import NmapArgumentError, NmapNotInstalledError
from nmass.models import Address, NmapRun
from nmass.utils import as_root


@dataclass
class Nmap:
    _bin_path: str = ""
    _args: list[str] = field(default_factory=lambda: [])

    def __post_init__(self):
        if self._bin_path == "":
            if w := shutil.which("nmap"):
                self._bin_path = w
            else:
                raise NmapNotInstalledError()

    def run(
        self,
        timeout: float | None = None,
        with_output: bool = True,
    ) -> NmapRun | None:
        """Run nmap command

        :param timeout: timeout for nmap process, defaults to None
        :param with_output: print nmap's output, defaults to True
        :return: NmapRun object or None
        """
        with tempfile.NamedTemporaryFile(delete_on_close=True) as xml_out:
            cmd = [self._bin_path, "-oX", xml_out.name, *self._args]
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    timeout=timeout,
                    capture_output=not with_output,
                )
            except subprocess.TimeoutExpired:
                logging.warn("nmap scanning timeout")
            except subprocess.CalledProcessError as e:
                logging.error(f"nmap's return code is {e.returncode}")
                logging.error(e.stderr.decode())
            except Exception as why:
                logging.exception(why)
            else:
                return NmapRun.from_xml(xml_out.read())

            return None

    def with_step(self, model: NmapRun) -> Self:
        # masscan 中同一个目标会有多个 host element
        targets = set()
        ports = set()
        for host in model.hosts:
            for addr in host.address:
                match addr:
                    case Address(addr=ipv4, addrtype="ipv4"):
                        targets.add(ipv4)
                    case Address(addr=ipv6, addrtype="ipv6"):
                        self.with_ipv6()
                        targets.add(ipv6)
                    case Address(addr=_, addrtype="mac"):
                        logging.warn("MAC is not support")
            for port in host.ports.ports:
                ports.add(port.portid)
        self.with_targets(*targets)
        self.with_ports(*ports)
        return self

    ### TARGET SPECIFICATION ###

    def with_targets(self, *targets: list[str]) -> Self:
        self._args.extend(targets)
        return self

    def with_target_exclusion(self, *targets: list[str]) -> Self:
        self._args.extend(("--exclude", ",".join(targets)))
        return self

    def with_target_input(self, input_filename: str) -> Self:
        self._args.extend(("-iL", input_filename))
        return self

    def with_target_exclusion_input(self, input_filename: str) -> Self:
        self._args.extend(("--excludefile", input_filename))
        return self

    def with_random_targets(self, number: int) -> Self:
        self._args.extend(("-iR", str(number)))
        return self

    ### HOST DISCOVERY ###

    def with_list_scan(self) -> Self:
        """List Scan - simply list targets to scan"""
        self._args.append("-sL")
        return self

    def with_ping_scan(self) -> Self:
        """Ping Scan - disable port scan"""
        self._args.append("-sn")
        return self

    def without_ping(self) -> Self:
        """Treat all hosts as online -- skip host discovery"""
        self._args.append("-Pn")
        return self

    # TODO: -PS/PA/PU/PY 应该只能选其一

    def with_syn_discovery(self, *ports: list[str]) -> Self:
        ports_str = ",".join(ports)
        self._args.append(f"-PS{ports_str}")
        return self

    def with_ack_discovery(self, *ports: list[str]) -> Self:
        ports_str = ",".join(ports)
        self._args.append(f"-PA{ports_str}")
        return self

    def with_udp_discovery(self, *ports: list[str]) -> Self:
        ports_str = ",".join(ports)
        self._args.append(f"-PU{ports_str}")
        return self

    def with_sctp_discovery(self, *ports: list[str]) -> Self:
        ports_str = ",".join(ports)
        self._args.append(f"-PY{ports_str}")
        return self

    # TODO: -PE/PP/PM 应该只能选其一

    def with_icmp_echo_discovery(self) -> Self:
        self._args.append("-PE")
        return self

    def with_icmp_timestamp_discovery(self) -> Self:
        self._args.append("-PP")
        return self

    def with_icmp_netmask_discovery(self) -> Self:
        self._args.append("-PM")
        return self

    def with_ip_protocol_ping_discovery(self, *protocols: list[str]) -> Self:
        protocols_str = ",".join(protocols)
        self._args.append(f"-PO{protocols_str}")
        return self

    # TODO: -n/R 应该只能选其一

    def without_dns_resolution(self) -> Self:
        self._args.append("-n")
        return self

    def with_forced_dns_resolution(self) -> Self:
        self._args.append("-R")
        return self

    def with_custom_dns_servers(self, *servers: list[str]) -> Self:
        servers_str = ",".join(servers)
        self._args.extend(("--dns-servers"), servers_str)
        return self

    def with_system_dns(self) -> Self:
        """Use OS's DNS resolver"""
        self._args.append("--system-dns")
        return self

    def with_traceroute(self) -> Self:
        self._args.append("--traceroute")
        return self

    ### SCAN TECHNIQUES ###

    @as_root
    def with_syn_scan(self) -> Self:
        self._args.append("-sS")
        return self

    def with_connect_scan(self) -> Self:
        self._args.append("-sT")
        return self

    def with_ack_scan(self) -> Self:
        self._args.append("-sA")
        return self

    def with_window_scan(self) -> Self:
        self._args.append("-sW")
        return self

    def with_maimon_scan(self) -> Self:
        self._args.append("-sM")
        return self

    def with_udp_scan(self) -> Self:
        self._args.append("-sU")
        return self

    def with_tcp_null_scan(self) -> Self:
        self._args.append("-sN")
        return self

    def with_tcp_fin_scan(self) -> Self:
        self._args.append("-sF")
        return self

    def with_tcp_xmas_scan(self) -> Self:
        self._args.append("-sX")
        return self

    class TCPFlag(enum.IntEnum):
        FlagNULL = 0
        FlagFIN = 1
        FlagSYN = 2
        FlagRST = 4
        FlagPSH = 8
        FlagACK = 16
        FlagURG = 32
        FlagECE = 64
        FlagCWR = 128
        FlagNS = 256

    # TODO: https://nmap.org/book/scan-methods-custom-scanflags.html
    def with_tcp_scan_flags(self, *flags: list[TCPFlag]) -> Self:
        total = 0
        for f in flags:
            total += int(f)

        self._args.extend(("--scanflags", str(total)))
        return self

    def with_idel_scan(self, zombie_host: str, probe_port: int) -> Self:
        self._args.append("-sI")
        if probe_port > 0:
            self._args.append(f"{zombie_host}:{probe_port}")
        else:
            self._args.append(zombie_host)
        return self

    def with_sctp_init_scan(self) -> Self:
        self._args.append("-sY")
        return self

    def with_sctp_cookie_echo_scan(self) -> Self:
        self._args.append("-sZ")
        return self

    def with_ip_protocol_scan(self) -> Self:
        self._args.append("-sO")
        return self

    def with_ftp_bounce_scan(self, ftp_relay_host: str) -> Self:
        self._args.extend(("-b", ftp_relay_host))
        return self

    ### PORT SPECIFICATION AND SCAN ORDER ###

    def with_ports(self, *ports: list[int | str]) -> Self:
        if type(ports[0]) is int:
            ports_str = ",".join([str(p) for p in ports])
        else:
            ports_str = ",".join(ports)

        # 多次调用 with_ports 添加端口
        place = -1
        for i, arg in enumerate(self._args):
            if arg == "-p":
                place = i
                break

        if place > 0:
            if i == len(self._args) - 1:
                self._args.append("")
            else:
                ports_str = self._args[place + 1] + "," + ports_str
            self._args[place + 1] = ports_str
        else:
            self._args.extend(("-p", ports_str))

        return self

    def with_port_exclusion(self, *ports: list[str]) -> Self:
        ports_str = ",".join(ports)
        self._args.extend(("--exclude-ports", ports_str))
        return self

    def with_fast_mode(self) -> Self:
        self._args.append("-F")
        return self

    def with_consecutive_port_scanning(self) -> Self:
        """Scan ports sequentially - don't randomize"""
        self._args.append("-r")
        return self

    def with_most_common_ports(self, top: int) -> Self:
        if not 0 < top <= 65535:
            raise NmapArgumentError(
                f"invalid argument value {top=}, port number should between 1 to 65535",
                nmap_arg="--top-ports",
            )
        self._args.extend(("--top-ports", str(top)))
        return self

    def with_port_ratio(self, ratio: float) -> Self:
        """Scan ports more common than <ratio>"""
        if not 0 < ratio < 1:
            raise NmapArgumentError(
                f"invalid argument value {ratio=}, should be between 0 to 1",
                nmap_arg="--port-ratio",
            )
        self._args.extend(("--port-ratio", str(ratio)))
        return self

    ### SERVICE/VERSION DETECTION ###

    def with_service_info(self) -> Self:
        self._args.append("-sV")
        return self

    def with_version_intensity(self, intensity: int = 7) -> Self:
        if not 0 <= intensity <= 9:
            raise NmapArgumentError(
                f"invalid argument value {intensity=}, please set from 0 (light) to 9 (try all probes)",
                nmap_arg="--version-intensity",
            )
        self._args.extend(("--version-intensity", str(intensity)))
        return self

    def with_version_light(self) -> Self:
        """Limit to most likely probes (intensity 2)"""
        self._args.append("--version-light")
        return self

    def with_version_all(self) -> Self:
        """Try every single probe (intensity 9)"""
        self._args.append("--version-all")
        return self

    def with_version_trace(self) -> Self:
        """Show detailed version scan activity (for debugging)"""
        self._args.append("--version-trace")
        return self

    ### SCRIPT SCAN ###

    def with_default_script(self) -> Self:
        self._args.append("-sC")
        return self

    def with_scripts(self, *scripts: list[str]) -> Self:
        scripts_str = ",".join(scripts)
        self._args.append(f"--script={scripts_str}")
        return self

    def with_script_arguments(self, **arguments: dict[str, str]) -> Self:
        script_args = "--script-args="
        for k, v in zip(arguments):
            if not v:
                script_args += f"{k},"
            else:
                script_args += f"{k}={v},"
        self._args.append(script_args[:-1])
        return self

    def with_script_arguments_file(self, filename: str) -> Self:
        self._args.append(f"--script-args-file={filename}")
        return self

    def with_script_trace(self) -> Self:
        """Show all data sent and received"""
        self._args.append("--script-trace")
        return self

    def with_script_update_db(self) -> Self:
        """Update the script database"""
        self._args.append("--script-updatedb")
        return self

    def with_script_help(self, *scripts: list[str]) -> Self:
        scripts_str = ",".join(scripts)
        self._args.append(f"--script-help={scripts_str}")
        return self

    ### OS DETECTION ###

    @as_root
    def with_os_detection(self) -> Self:
        self._args.append("-O")
        return self

    @as_root
    def with_osscan_limit(self) -> Self:
        self._args.append("--osscan-limit")
        return self

    @as_root
    def with_osscan_guess(self) -> Self:
        self._args.append("--osscan-guess")
        return self

    ### TIMING AND PERFORMANCE ###

    class TimingTemplate(enum.IntEnum):
        """https://nmap.org/book/performance-timing-templates.html"""

        Paranoid = 0
        Sneaky = 1
        Polite = 2
        Normal = 3
        Aggressive = 4
        Insane = 5

    def with_timing_template(self, template: TimingTemplate) -> Self:
        self._args.append(f"-T{int(template)}")
        return self

    # TODO:
    # --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
    # --min-parallelism/max-parallelism <numprobes>: Probe parallelization
    # --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies probe round trip time.
    # --max-retries <tries>: Caps number of port scan probe retransmissions.
    # --host-timeout <time>: Give up on target after this long
    # --scan-delay/--max-scan-delay <time>: Adjust delay between probes
    # --min-rate <number>: Send packets no slower than <number> per second
    # --max-rate <number>: Send packets no faster than <number> per second

    ### FIREWALL/IDS EVASION AND SPOOFING ###

    # TODO: 可以重复使用 -f 来继续减少切片的数量？（大小？）
    def with_fragment_packets(self) -> Self:
        self._args.append("-f")
        return self

    def with_mtu(self, offset: int) -> Self:
        if offset % 8 != 0:
            raise NmapArgumentError(
                f"invalid argument value {offset=}, the offset must be a multiple of eight",
                nmap_arg="--mtu",
            )
        self._args.extend(("--mtu", str(offset)))
        return self

    def with_decoys(self, *decoys: list[str]) -> Self:
        decoys_str = ",".join(decoys)
        self._args.extend(("-D", decoys_str))
        return self

    def with_spoof_address(self, ip: str) -> Self:
        self._args.extend(("-S", ip))
        return self

    def with_interface(self, iface: str) -> Self:
        self._args.extend(("-e", iface))
        return self

    def with_source_port(self, port: int) -> Self:
        self._args.extend(("--source-port", str(port)))
        return self

    def with_proxies(self, *proxies: list[str]) -> Self:
        proxies_str = ",".join(proxies)
        self._args.extend(("--proxies", proxies_str))
        return self

    def with_hex_data(self, data: str) -> Self:
        self._args.extend(("--data", data))
        return self

    def with_ascii_data(self, data: str) -> Self:
        self._args.extend(("--data-string", data))
        return self

    def with_data_length(self, length: int) -> Self:
        self._args.extend(("--data-length", str(length)))
        return self

    def with_ip_options(self, options: str) -> Self:
        self._args.extend(("--ip-options", options))
        return self

    def with_time_to_live(self, ttl: int) -> Self:
        if not 0 < ttl < 225:
            raise NmapArgumentError(
                f"invalid argument value {ttl=}, should be between 0 to 225",
                nmap_arg="-ttl",
            )
        self._args.extend(("-ttl", str(ttl)))
        return self

    def with_spoof_mac(self, mac: str) -> Self:
        self._args.extend(("--spoof-mac", mac))
        return self

    def with_bad_sum(self) -> Self:
        """Send packets with a bogus TCP/UDP/SCTP checksum"""
        self._args.append("--badsum")
        return self

    ### OUTPUT ###

    def with_verbose(self, level: int = 1) -> Self:
        self._args.append("-" + "v" * level)
        return self

    # TODO:
    # -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3, and Grepable format, respectively, to the given filename.
    # -oA <basename>: Output in the three major formats at once
    # -d: Increase debugging level (use -dd or more for greater effect)
    # --reason: Display the reason a port is in a particular state
    # --open: Only show open (or possibly open) ports
    # --packet-trace: Show all packets sent and received
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
        self._args.append("-6")
        return self

    @as_root
    def with_aggressive_scan(self) -> Self:
        self._args.append("-A")
        return self

    def with_data_dir(self, dirname: str) -> Self:
        self._args.extend(("--datadir", dirname))
        return self

    def with_send_ethernet(self) -> Self:
        self._args.append("--send-eth")
        return self

    def with_send_ip(self) -> Self:
        self._args.append("--send-ip")
        return self

    def with_privileged(self) -> Self:
        self._args.append("--privileged")
        return self

    def without_privileged(self) -> Self:
        self._args.append("--unprivileged")
        return self
