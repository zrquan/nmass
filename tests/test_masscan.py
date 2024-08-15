import pytest

from nmass import Masscan


@pytest.fixture
def masscan_instance():
    return Masscan(bin_path="/usr/bin/masscan")


def test_with_rate(masscan_instance):
    rate = 1000
    masscan_instance.with_rate(rate)
    assert (
        "--rate" in masscan_instance._args
    ), f"Expected '--rate' in args, got {masscan_instance._args}"
    assert (
        str(rate) in masscan_instance._args
    ), f"Expected '{rate}' in args, got {masscan_instance._args}"


def test_with_banners(masscan_instance):
    masscan_instance.with_banners()
    assert (
        "--banners" in masscan_instance._args
    ), f"Expected '--banners' in args, got {masscan_instance._args}"


def test_with_config(masscan_instance):
    filename = "/path/to/config.txt"
    masscan_instance.with_config(filename)
    assert "-c" in masscan_instance._args, f"Expected '-c' in args, got {masscan_instance._args}"
    assert (
        filename in masscan_instance._args
    ), f"Expected '{filename}' in args, got {masscan_instance._args}"


def test_with_resume(masscan_instance):
    filename = "/path/to/resume.txt"
    masscan_instance.with_resume(filename)
    assert (
        "--resume" in masscan_instance._args
    ), f"Expected '--resume' in args, got {masscan_instance._args}"
    assert (
        filename in masscan_instance._args
    ), f"Expected '{filename}' in args, got {masscan_instance._args}"


def test_echo_config(masscan_instance):
    masscan_instance.echo_config()
    assert (
        "--echo" in masscan_instance._args
    ), f"Expected '--echo' in args, got {masscan_instance._args}"


def test_with_adapter(masscan_instance):
    interface = "eth0"
    masscan_instance.with_adapter(interface)
    assert "-e" in masscan_instance._args, f"Expected '-e' in args, got {masscan_instance._args}"
    assert (
        interface in masscan_instance._args
    ), f"Expected '{interface}' in args, got {masscan_instance._args}"


def test_with_adapter_ip(masscan_instance):
    ip = "192.168.1.1"
    masscan_instance.with_adapter_ip(ip)
    assert (
        "--adapter-ip" in masscan_instance._args
    ), f"Expected '--adapter-ip' in args, got {masscan_instance._args}"
    assert ip in masscan_instance._args, f"Expected '{ip}' in args, got {masscan_instance._args}"


def test_with_adapter_port(masscan_instance):
    port = 8080
    masscan_instance.with_adapter_port(port)
    assert (
        "--adapter-port" in masscan_instance._args
    ), f"Expected '--adapter-port' in args, got {masscan_instance._args}"
    assert (
        str(port) in masscan_instance._args
    ), f"Expected '{port}' in args, got {masscan_instance._args}"


def test_with_adapter_mac(masscan_instance):
    mac_address = "00:11:22:33:44:55"
    masscan_instance.with_adapter_mac(mac_address)
    assert (
        "--adapter-mac" in masscan_instance._args
    ), f"Expected '--adapter-mac' in args, got {masscan_instance._args}"
    assert (
        mac_address in masscan_instance._args
    ), f"Expected '{mac_address}' in args, got {masscan_instance._args}"


def test_with_router_mac(masscan_instance):
    router_mac = "66:77:88:99:AA:BB"
    masscan_instance.with_router_mac(router_mac)
    assert (
        "--router-mac" in masscan_instance._args
    ), f"Expected '--router-mac' in args, got {masscan_instance._args}"
    assert (
        router_mac in masscan_instance._args
    ), f"Expected '{router_mac}' in args, got {masscan_instance._args}"


def test_with_ping(masscan_instance):
    masscan_instance.with_ping()
    assert (
        "--ping" in masscan_instance._args
    ), f"Expected '--ping' in args, got {masscan_instance._args}"


def test_with_append_output(masscan_instance):
    masscan_instance.with_append_output()
    assert (
        "--append-output" in masscan_instance._args
    ), f"Expected '--append-output' in args, got {masscan_instance._args}"


def test_with_retries(masscan_instance):
    retries = 3
    masscan_instance.with_retries(retries)
    assert (
        "--retries" in masscan_instance._args
    ), f"Expected '--retries' in args, got {masscan_instance._args}"
    assert (
        str(retries) in masscan_instance._args
    ), f"Expected '{retries}' in args, got {masscan_instance._args}"


def test_with_pcap_payloads(masscan_instance):
    filename = "/path/to/payloads.pcap"
    masscan_instance.with_pcap_payloads(filename)
    assert (
        "--pcap-payloads" in masscan_instance._args
    ), f"Expected '--pcap-payloads' in args, got {masscan_instance._args}"
    assert (
        filename in masscan_instance._args
    ), f"Expected '{filename}' in args, got {masscan_instance._args}"


def test_with_nmap_payloads(masscan_instance):
    filename = "/path/to/nmap_payloads.txt"
    masscan_instance.with_nmap_payloads(filename)
    assert (
        "--nmap-payloads" in masscan_instance._args
    ), f"Expected '--nmap-payloads' in args, got {masscan_instance._args}"
    assert (
        filename in masscan_instance._args
    ), f"Expected '{filename}' in args, got {masscan_instance._args}"


def test_with_http_user_agent(masscan_instance):
    user_agent = "Mozilla/5.0"
    masscan_instance.with_http_user_agent(user_agent)
    assert (
        "--http-user-agent" in masscan_instance._args
    ), f"Expected '--http-user-agent' in args, got {masscan_instance._args}"
    assert (
        user_agent in masscan_instance._args
    ), f"Expected '{user_agent}' in args, got {masscan_instance._args}"


def test_without_closed_ports(masscan_instance):
    masscan_instance.without_closed_ports()
    assert (
        "--open-only" in masscan_instance._args
    ), f"Expected '--open-only' in args, got {masscan_instance._args}"


def test_with_pcap(masscan_instance):
    filename = "/path/to/output.pcap"
    masscan_instance.with_pcap(filename)
    assert (
        "--pcap" in masscan_instance._args
    ), f"Expected '--pcap' in args, got {masscan_instance._args}"
    assert (
        filename in masscan_instance._args
    ), f"Expected '{filename}' in args, got {masscan_instance._args}"


def test_with_packet_trace(masscan_instance):
    masscan_instance.with_packet_trace()
    assert (
        "--packet-trace" in masscan_instance._args
    ), f"Expected '--packet-trace' in args, got {masscan_instance._args}"


def test_with_pfring(masscan_instance):
    masscan_instance.with_pfring()
    assert (
        "--pfring" in masscan_instance._args
    ), f"Expected '--pfring' in args, got {masscan_instance._args}"


def test_with_resume_index(masscan_instance):
    index = 10
    masscan_instance.with_resume_index(index)
    assert (
        "--resume-index" in masscan_instance._args
    ), f"Expected '--resume-index' in args, got {masscan_instance._args}"
    assert (
        str(index) in masscan_instance._args
    ), f"Expected '{index}' in args, got {masscan_instance._args}"


def test_with_resume_count(masscan_instance):
    count = 100
    masscan_instance.with_resume_count(count)
    assert (
        "--resume-count" in masscan_instance._args
    ), f"Expected '--resume-count' in args, got {masscan_instance._args}"
    assert (
        str(count) in masscan_instance._args
    ), f"Expected '{count}' in args, got {masscan_instance._args}"


def test_with_shards(masscan_instance):
    shard_id = 1
    total_shards = 4
    masscan_instance.with_shards(shard_id, total_shards)
    expected_arg = f"--shards {shard_id}/{total_shards}"
    assert expected_arg in " ".join(
        masscan_instance._args
    ), f"Expected '{expected_arg}' in args, got {masscan_instance._args}"


def test_with_rotate(masscan_instance):
    time = "hourly"
    masscan_instance.with_rotate(time)
    assert (
        "--rotate" in masscan_instance._args
    ), f"Expected '--rotate' in args, got {masscan_instance._args}"
    assert (
        time in masscan_instance._args
    ), f"Expected '{time}' in args, got {masscan_instance._args}"


def test_with_rotate_offset(masscan_instance):
    offset = "30min"
    masscan_instance.with_rotate_offset(offset)
    assert (
        "--rotate-offset" in masscan_instance._args
    ), f"Expected '--rotate-offset' in args, got {masscan_instance._args}"
    assert (
        offset in masscan_instance._args
    ), f"Expected '{offset}' in args, got {masscan_instance._args}"


def test_with_rotate_dir(masscan_instance):
    directory = "/path/to/rotate"
    masscan_instance.with_rotate_dir(directory)
    assert (
        "--rotate-dir" in masscan_instance._args
    ), f"Expected '--rotate-dir' in args, got {masscan_instance._args}"
    assert (
        directory in masscan_instance._args
    ), f"Expected '{directory}' in args, got {masscan_instance._args}"


def test_with_seed(masscan_instance):
    seed = "123456"
    masscan_instance.with_seed(seed)
    assert (
        "--seed" in masscan_instance._args
    ), f"Expected '--seed' in args, got {masscan_instance._args}"
    assert (
        seed in masscan_instance._args
    ), f"Expected '{seed}' in args, got {masscan_instance._args}"


def test_with_regress(masscan_instance):
    masscan_instance.with_regress()
    assert (
        "--regress" in masscan_instance._args
    ), f"Expected '--regress' in args, got {masscan_instance._args}"


def test_with_ttl(masscan_instance):
    ttl = 64
    masscan_instance.with_ttl(ttl)
    assert (
        "--ttl" in masscan_instance._args
    ), f"Expected '--ttl' in args, got {masscan_instance._args}"
    assert (
        str(ttl) in masscan_instance._args
    ), f"Expected '{ttl}' in args, got {masscan_instance._args}"


def test_with_wait(masscan_instance):
    seconds = 10
    masscan_instance.with_wait(seconds)
    assert (
        "--wait" in masscan_instance._args
    ), f"Expected '--wait' in args, got {masscan_instance._args}"
    assert (
        str(seconds) in masscan_instance._args
    ), f"Expected '{seconds}' in args, got {masscan_instance._args}"


def test_with_offline(masscan_instance):
    masscan_instance.with_offline()
    assert (
        "--offline" in masscan_instance._args
    ), f"Expected '--offline' in args, got {masscan_instance._args}"


def test_with_sL(masscan_instance):
    masscan_instance.with_sL()
    assert "-sL" in masscan_instance._args, f"Expected '-sL' in args, got {masscan_instance._args}"


def test_with_output_file(masscan_instance):
    filename = "output.json"
    format = "J"
    masscan_instance.with_output_file(filename, format)
    expected_arg = f"-o{format} {filename}"
    assert expected_arg in " ".join(
        masscan_instance._args
    ), f"Expected '{expected_arg}' in args, got {masscan_instance._args}"


def test_run_masscan(masscan_instance):
    with pytest.raises(PermissionError) as err:
        masscan_instance.run()
    assert str(err.value).endswith("needs to be executed as root.")
