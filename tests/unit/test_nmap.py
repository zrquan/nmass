import pytest

from nmass import Nmap
from nmass.model.enums import TCPFlag, TimingTemplate


@pytest.fixture
def nmap_instance():
    return Nmap(bin_path="/usr/bin/nmap")


def test_version(nmap_instance):
    assert nmap_instance.info.version.startswith("7.")


def test_iflist(nmap_instance):
    loopback = nmap_instance.iflist().interfaces[0]
    assert loopback.device == "lo"
    assert str(loopback.ip) == "127.0.0.1"
    assert loopback.ip.is_loopback is True
    assert loopback.is_up is True


def test_with_random_targets(nmap_instance):
    number = 5
    nmap_instance.with_random_targets(number)
    assert "-iR" in nmap_instance._args, f"Expected '-iR' in args, got {nmap_instance._args}"
    assert str(number) in nmap_instance._args, f"Expected '{number}' in args, got {nmap_instance._args}"


def test_with_list_scan(nmap_instance):
    nmap_instance.with_list_scan()
    assert "-sL" in nmap_instance._args, f"Expected '-sL' in args, got {nmap_instance._args}"


def test_with_ping_scan(nmap_instance):
    nmap_instance.with_ping_scan()
    assert "-sn" in nmap_instance._args, f"Expected '-sn' in args, got {nmap_instance._args}"


def test_without_ping(nmap_instance):
    nmap_instance.without_ping()
    assert "-Pn" in nmap_instance._args, f"Expected '-Pn' in args, got {nmap_instance._args}"


def test_with_syn_discovery(nmap_instance):
    ports = ["22", "80"]
    nmap_instance.with_syn_discovery(*ports)
    expected_arg = f"-PS{','.join(ports)}"
    assert expected_arg in nmap_instance._args, f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_ack_discovery(nmap_instance):
    ports = ["22", "80"]
    nmap_instance.with_ack_discovery(*ports)
    expected_arg = f"-PA{','.join(ports)}"
    assert expected_arg in nmap_instance._args, f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_udp_discovery(nmap_instance):
    ports = ["53", "123"]
    nmap_instance.with_udp_discovery(*ports)
    expected_arg = f"-PU{','.join(ports)}"
    assert expected_arg in nmap_instance._args, f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_sctp_discovery(nmap_instance):
    ports = ["80", "443"]
    nmap_instance.with_sctp_discovery(*ports)
    expected_arg = f"-PY{','.join(ports)}"
    assert expected_arg in nmap_instance._args, f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_icmp_echo_discovery(nmap_instance):
    nmap_instance.with_icmp_echo_discovery()
    assert "-PE" in nmap_instance._args, f"Expected '-PE' in args, got {nmap_instance._args}"


def test_with_icmp_timestamp_discovery(nmap_instance):
    nmap_instance.with_icmp_timestamp_discovery()
    assert "-PP" in nmap_instance._args, f"Expected '-PP' in args, got {nmap_instance._args}"


def test_with_icmp_netmask_discovery(nmap_instance):
    nmap_instance.with_icmp_netmask_discovery()
    assert "-PM" in nmap_instance._args, f"Expected '-PM' in args, got {nmap_instance._args}"


def test_with_ip_protocol_ping_discovery(nmap_instance):
    protocols = ["tcp", "udp"]
    nmap_instance.with_ip_protocol_ping_discovery(*protocols)
    expected_arg = f"-PO{','.join(protocols)}"
    assert expected_arg in nmap_instance._args, f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_without_dns_resolution(nmap_instance):
    nmap_instance.without_dns_resolution()
    assert "-n" in nmap_instance._args, f"Expected '-n' in args, got {nmap_instance._args}"


def test_with_forced_dns_resolution(nmap_instance):
    nmap_instance.with_forced_dns_resolution()
    assert "-R" in nmap_instance._args, f"Expected '-R' in args, got {nmap_instance._args}"


def test_with_custom_dns_servers(nmap_instance):
    servers = ["8.8.8.8", "8.8.4.4"]
    nmap_instance.with_custom_dns_servers(*servers)
    expected_arg = f"--dns-servers {','.join(servers)}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_system_dns(nmap_instance):
    nmap_instance.with_system_dns()
    assert "--system-dns" in nmap_instance._args, f"Expected '--system-dns' in args, got {nmap_instance._args}"


def test_with_traceroute(nmap_instance):
    nmap_instance.with_traceroute()
    assert "--traceroute" in nmap_instance._args, f"Expected '--traceroute' in args, got {nmap_instance._args}"


def test_with_syn_scan(nmap_instance):
    with pytest.raises(PermissionError) as err:
        nmap_instance.with_syn_scan()
    assert str(err.value).endswith("needs to be executed as root.")


def test_with_connect_scan(nmap_instance):
    nmap_instance.with_connect_scan()
    assert "-sT" in nmap_instance._args, f"Expected '-sT' in args, got {nmap_instance._args}"


def test_with_ack_scan(nmap_instance):
    nmap_instance.with_ack_scan()
    assert "-sA" in nmap_instance._args, f"Expected '-sA' in args, got {nmap_instance._args}"


def test_with_window_scan(nmap_instance):
    nmap_instance.with_window_scan()
    assert "-sW" in nmap_instance._args, f"Expected '-sW' in args, got {nmap_instance._args}"


def test_with_maimon_scan(nmap_instance):
    nmap_instance.with_maimon_scan()
    assert "-sM" in nmap_instance._args, f"Expected '-sM' in args, got {nmap_instance._args}"


def test_with_udp_scan(nmap_instance):
    nmap_instance.with_udp_scan()
    assert "-sU" in nmap_instance._args, f"Expected '-sU' in args, got {nmap_instance._args}"


def test_with_tcp_null_scan(nmap_instance):
    nmap_instance.with_tcp_null_scan()
    assert "-sN" in nmap_instance._args, f"Expected '-sN' in args, got {nmap_instance._args}"


def test_with_tcp_fin_scan(nmap_instance):
    nmap_instance.with_tcp_fin_scan()
    assert "-sF" in nmap_instance._args, f"Expected '-sF' in args, got {nmap_instance._args}"


def test_with_tcp_xmas_scan(nmap_instance):
    nmap_instance.with_tcp_xmas_scan()
    assert "-sX" in nmap_instance._args, f"Expected '-sX' in args, got {nmap_instance._args}"


def test_with_tcp_scan_flags(nmap_instance):
    flags = [TCPFlag.FIN, TCPFlag.URG]
    nmap_instance.with_tcp_scan_flags(*flags)
    expected_arg = "--scanflags 33"  # FlagFIN (1) + FlagURG (32)
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_idle_scan(nmap_instance):
    zombie_host = "192.168.1.1"
    probe_port = 80
    nmap_instance.with_idle_scan(zombie_host, probe_port)
    expected_arg = f"-sI {zombie_host}:{probe_port}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_sctp_init_scan(nmap_instance):
    nmap_instance.with_sctp_init_scan()
    assert "-sY" in nmap_instance._args, f"Expected '-sY' in args, got {nmap_instance._args}"


def test_with_sctp_cookie_echo_scan(nmap_instance):
    nmap_instance.with_sctp_cookie_echo_scan()
    assert "-sZ" in nmap_instance._args, f"Expected '-sZ' in args, got {nmap_instance._args}"


def test_with_ip_protocol_scan(nmap_instance):
    nmap_instance.with_ip_protocol_scan()
    assert "-sO" in nmap_instance._args, f"Expected '-sO' in args, got {nmap_instance._args}"


def test_with_ftp_bounce_scan(nmap_instance):
    ftp_relay_host = "192.168.1.2"
    nmap_instance.with_ftp_bounce_scan(ftp_relay_host)
    expected_arg = f"-b {ftp_relay_host}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_port_exclusion(nmap_instance):
    ports = ["22", "80"]
    nmap_instance.with_port_exclusion(*ports)
    expected_arg = f"--exclude-ports {','.join(ports)}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_fast_mode(nmap_instance):
    nmap_instance.with_fast_mode()
    assert "-F" in nmap_instance._args, f"Expected '-F' in args, got {nmap_instance._args}"


def test_with_consecutive_port_scanning(nmap_instance):
    nmap_instance.with_consecutive_port_scanning()
    assert "-r" in nmap_instance._args, f"Expected '-r' in args, got {nmap_instance._args}"


def test_with_most_common_ports(nmap_instance):
    top = 100
    nmap_instance.with_most_common_ports(top)
    expected_arg = f"--top-ports {top}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_port_ratio(nmap_instance):
    ratio = 0.5
    nmap_instance.with_port_ratio(ratio)
    expected_arg = f"--port-ratio {ratio}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_service_info(nmap_instance):
    nmap_instance.with_service_info()
    assert "-sV" in nmap_instance._args, f"Expected '-sV' in args, got {nmap_instance._args}"


def test_with_version_intensity(nmap_instance):
    intensity = 5
    nmap_instance.with_version_intensity(intensity)
    expected_arg = f"--version-intensity {intensity}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_version_light(nmap_instance):
    nmap_instance.with_version_light()
    assert "--version-light" in nmap_instance._args, f"Expected '--version-light' in args, got {nmap_instance._args}"


def test_with_version_all(nmap_instance):
    nmap_instance.with_version_all()
    assert "--version-all" in nmap_instance._args, f"Expected '--version-all' in args, got {nmap_instance._args}"


def test_with_version_trace(nmap_instance):
    nmap_instance.with_version_trace()
    assert "--version-trace" in nmap_instance._args, f"Expected '--version-trace' in args, got {nmap_instance._args}"


def test_with_default_script(nmap_instance):
    nmap_instance.with_default_script()
    assert "-sC" in nmap_instance._args, f"Expected '-sC' in args, got {nmap_instance._args}"


def test_with_scripts(nmap_instance):
    scripts = ["http-title", "ssh-hostkey"]
    nmap_instance.with_scripts(*scripts)
    expected_arg = f"--script={','.join(scripts)}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_script_arguments(nmap_instance):
    args = {"user": "admin", "pass": "1234"}
    nmap_instance.with_script_arguments(**args)
    expected_arg = "--script-args=user=admin,pass=1234"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_script_arguments_file(nmap_instance):
    filename = "/path/to/args.txt"
    nmap_instance.with_script_arguments_file(filename)
    expected_arg = f"--script-args-file={filename}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_script_trace(nmap_instance):
    nmap_instance.with_script_trace()
    assert "--script-trace" in nmap_instance._args, f"Expected '--script-trace' in args, got {nmap_instance._args}"


def test_with_script_update_db(nmap_instance):
    nmap_instance.with_script_update_db()
    assert (
        "--script-updatedb" in nmap_instance._args
    ), f"Expected '--script-updatedb' in args, got {nmap_instance._args}"


def test_with_script_help(nmap_instance):
    scripts = ["http-title", "ssh-hostkey"]
    nmap_instance.with_script_help(*scripts)
    expected_arg = f"--script-help={','.join(scripts)}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_os_detection(nmap_instance):
    with pytest.raises(PermissionError) as err:
        nmap_instance.with_os_detection()
    assert str(err.value).endswith("needs to be executed as root.")


def test_with_osscan_limit(nmap_instance):
    with pytest.raises(PermissionError) as err:
        nmap_instance.with_osscan_limit()
    assert str(err.value).endswith("needs to be executed as root.")


def test_with_osscan_guess(nmap_instance):
    with pytest.raises(PermissionError) as err:
        nmap_instance.with_osscan_guess()
    assert str(err.value).endswith("needs to be executed as root.")


def test_with_timing_template(nmap_instance):
    template = TimingTemplate.Aggressive
    nmap_instance.with_timing_template(template)
    expected_arg = f"-T{int(template)}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_hostgroup_size(nmap_instance):
    nmap_instance.with_hostgroup_size(min=10, max=50)
    assert "--min-hostgroup 10" in " ".join(
        nmap_instance._args
    ), f"Expected '--min-hostgroup 10' in args, got {nmap_instance._args}"
    assert "--max-hostgroup 50" in " ".join(
        nmap_instance._args
    ), f"Expected '--max-hostgroup 50' in args, got {nmap_instance._args}"


def test_with_parallelism(nmap_instance):
    nmap_instance.with_parallelism(min=10, max=50)
    assert "--min-parallelism 10" in " ".join(
        nmap_instance._args
    ), f"Expected '--min-parallelism 10' in args, got {nmap_instance._args}"
    assert "--max-parallelism 50" in " ".join(
        nmap_instance._args
    ), f"Expected '--max-parallelism 50' in args, got {nmap_instance._args}"


def test_with_rtt_timeout(nmap_instance):
    nmap_instance.with_rtt_timeout(min=100, max=500, initial=200)
    assert "--min-rtt-timeout 100" in " ".join(
        nmap_instance._args
    ), f"Expected '--min-rtt-timeout 100' in args, got {nmap_instance._args}"
    assert "--max-rtt-timeout 500" in " ".join(
        nmap_instance._args
    ), f"Expected '--max-rtt-timeout 500' in args, got {nmap_instance._args}"
    assert "--initial-rtt-timeout 200" in " ".join(
        nmap_instance._args
    ), f"Expected '--initial-rtt-timeout 200' in args, got {nmap_instance._args}"


def test_with_max_retries(nmap_instance):
    tries = 3
    nmap_instance.with_max_retries(tries)
    expected_arg = f"--max-retries {tries}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_host_timeout(nmap_instance):
    timeout = 10000
    nmap_instance.with_host_timeout(timeout)
    expected_arg = f"--host-timeout {timeout}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_scan_delay(nmap_instance):
    nmap_instance.with_scan_delay(time=100, max_time=500)
    assert "--scan-delay 100" in " ".join(
        nmap_instance._args
    ), f"Expected '--scan-delay 100' in args, got {nmap_instance._args}"
    assert "--max-scan-delay 500" in " ".join(
        nmap_instance._args
    ), f"Expected '--max-scan-delay 500' in args, got {nmap_instance._args}"


def test_with_rate(nmap_instance):
    nmap_instance.with_rate(min=100, max=500)
    assert "--min-rate 100" in " ".join(
        nmap_instance._args
    ), f"Expected '--min-rate 100' in args, got {nmap_instance._args}"
    assert "--max-rate 500" in " ".join(
        nmap_instance._args
    ), f"Expected '--max-rate 500' in args, got {nmap_instance._args}"


def test_with_fragment_packets(nmap_instance):
    nmap_instance.with_fragment_packets()
    assert "-f" in nmap_instance._args, f"Expected '-f' in args, got {nmap_instance._args}"


def test_with_mtu(nmap_instance):
    offset = 16
    nmap_instance.with_mtu(offset)
    expected_arg = f"--mtu {offset}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_decoys(nmap_instance):
    decoys = ["192.168.1.1", "10.0.0.1"]
    nmap_instance.with_decoys(*decoys)
    expected_arg = f"-D {','.join(decoys)}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_spoof_address(nmap_instance):
    ip = "192.168.1.100"
    nmap_instance.with_spoof_address(ip)
    expected_arg = f"-S {ip}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_interface(nmap_instance):
    iface = "eth0"
    nmap_instance.with_interface(iface)
    expected_arg = f"-e {iface}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_source_port(nmap_instance):
    port = 12345
    nmap_instance.with_source_port(port)
    expected_arg = f"--source-port {port}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_proxies(nmap_instance):
    proxies = ["http://proxy1", "http://proxy2"]
    nmap_instance.with_proxies(*proxies)
    expected_arg = f"--proxies {','.join(proxies)}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_hex_data(nmap_instance):
    data = "deadbeef"
    nmap_instance.with_hex_data(data)
    expected_arg = f"--data {data}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_ascii_data(nmap_instance):
    data = "hello"
    nmap_instance.with_ascii_data(data)
    expected_arg = f"--data-string {data}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_data_length(nmap_instance):
    length = 16
    nmap_instance.with_data_length(length)
    expected_arg = f"--data-length {length}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_ip_options(nmap_instance):
    options = "nop,ts"
    nmap_instance.with_ip_options(options)
    expected_arg = f"--ip-options {options}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_time_to_live(nmap_instance):
    ttl = 128
    nmap_instance.with_time_to_live(ttl)
    expected_arg = f"-ttl {ttl}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_spoof_mac(nmap_instance):
    mac = "00:11:22:33:44:55"
    nmap_instance.with_spoof_mac(mac)
    expected_arg = f"--spoof-mac {mac}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_bad_sum(nmap_instance):
    nmap_instance.with_bad_sum()
    assert "--badsum" in nmap_instance._args, f"Expected '--badsum' in args, got {nmap_instance._args}"


def test_with_output_file(nmap_instance):
    filename = "output.txt"
    nmap_instance.with_output_file(filename, format="N")
    expected_arg = f"-oN {filename}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_verbose(nmap_instance):
    level = 2
    nmap_instance.with_verbose(level)
    expected_arg = f"-{'v' * level}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_debugging(nmap_instance):
    level = 2
    nmap_instance.with_debugging(level)
    expected_arg = f"-{'d' * level}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_reason(nmap_instance):
    nmap_instance.with_reason()
    assert "--reason" in nmap_instance._args, f"Expected '--reason' in args, got {nmap_instance._args}"


def test_without_closed_ports(nmap_instance):
    nmap_instance.without_closed_ports()
    assert "--open" in nmap_instance._args, f"Expected '--open' in args, got {nmap_instance._args}"


def test_with_packet_trace(nmap_instance):
    nmap_instance.with_packet_trace()
    assert "--packet-trace" in nmap_instance._args, f"Expected '--packet-trace' in args, got {nmap_instance._args}"


def test_with_ipv6(nmap_instance):
    nmap_instance.with_ipv6()
    assert "-6" in nmap_instance._args, f"Expected '-6' in args, got {nmap_instance._args}"


def test_with_aggressive_scan(nmap_instance):
    with pytest.raises(PermissionError) as err:
        nmap_instance.with_aggressive_scan()
    assert str(err.value).endswith("needs to be executed as root.")


def test_with_data_dir(nmap_instance):
    dirname = "/path/to/data"
    nmap_instance.with_data_dir(dirname)
    expected_arg = f"--datadir {dirname}"
    assert expected_arg in " ".join(
        nmap_instance._args
    ), f"Expected '{expected_arg}' in args, got {nmap_instance._args}"


def test_with_send_ethernet(nmap_instance):
    nmap_instance.with_send_ethernet()
    assert "--send-eth" in nmap_instance._args, f"Expected '--send-eth' in args, got {nmap_instance._args}"


def test_with_send_ip(nmap_instance):
    nmap_instance.with_send_ip()
    assert "--send-ip" in nmap_instance._args, f"Expected '--send-ip' in args, got {nmap_instance._args}"


def test_with_privileged(nmap_instance):
    nmap_instance.with_privileged()
    assert "--privileged" in nmap_instance._args, f"Expected '--privileged' in args, got {nmap_instance._args}"


def test_without_privileged(nmap_instance):
    nmap_instance.without_privileged()
    assert "--unprivileged" in nmap_instance._args, f"Expected '--unprivileged' in args, got {nmap_instance._args}"
