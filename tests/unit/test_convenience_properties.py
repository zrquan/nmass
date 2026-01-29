"""Test convenience properties for better UX."""

from pathlib import Path

from nmass.model.elements import NmapRun

DATA_DIR = Path(__file__).parent / "data"


def test_host_convenience_properties():
    """Test Host convenience properties that flatten nested attributes."""
    xml = DATA_DIR / "1_os_banner_scripts.xml"
    result = NmapRun.from_xml(xml.read_bytes())
    host = result.hosts[0]

    # Test state property (flattens host.status.state)
    assert host.state is not None
    assert host.state == host.status.state

    # Test port_list property (flattens host.ports.ports)
    assert len(host.port_list) == len(host.ports.ports)
    assert len(host.port_list) == 8

    # Test extra_ports property
    assert len(host.extra_ports) == len(host.ports.extraports)

    # Test address property
    assert host.address is not None
    assert host.address.addr == "127.0.0.1"

    # Test ipv4 property
    assert host.ipv4 == "127.0.0.1"

    # Test hostname property
    assert host.hostname == "localhost"

    # Test os_matches property (flattens host.os.osmatches)
    # In this XML, there are no <osmatch> elements, only <osclass> directly under <os>
    # So os_matches should be None
    assert host.os_matches is None


def test_port_convenience_properties():
    """Test Port convenience properties that flatten nested attributes."""
    xml = DATA_DIR / "1_os_banner_scripts.xml"
    result = NmapRun.from_xml(xml.read_bytes())
    port = result.hosts[0].port_list[0]  # Using new convenience property

    # Test port_state property (flattens port.state.state)
    assert port.port_state == port.state.state
    assert port.port_state.value == "open"

    # Test reason property (flattens port.state.reason)
    assert port.reason == port.state.reason
    assert port.reason == "syn-ack"

    # Test service_name property
    assert port.service_name == port.service.name
    assert port.service_name == "ssh"

    # Test product property
    assert port.product == port.service.product
    assert port.product == "OpenSSH"

    # Test version property
    assert port.version == port.service.version
    assert port.version == "5.3"


def test_nmaprun_convenience_properties():
    """Test NmapRun convenience properties that flatten nested attributes."""
    xml = DATA_DIR / "1_os_banner_scripts.xml"
    result = NmapRun.from_xml(xml.read_bytes())

    # Test host_stats property (flattens result.stats.hosts)
    assert result.host_stats == result.stats.hosts

    # Test finished property (flattens result.stats.finished)
    assert result.finished == result.stats.finished

    # Test hosts_up, hosts_down, hosts_total properties
    assert result.hosts_up == 1
    assert result.hosts_down == 0
    assert result.hosts_total == 1


def test_convenience_properties_with_none_values():
    """Test that convenience properties handle None values gracefully."""
    xml = DATA_DIR / "dionaea_scan.xml"
    result = NmapRun.from_xml(xml.read_bytes())

    # Test with masscan output where some fields are None
    if result.hosts:
        host = result.hosts[0]

        # Test properties that might be None
        if host.os is None:
            assert host.os_matches is None

        # Test mac address (might not exist)
        if not any(addr.addrtype == "mac" for addr in host.addresses):
            assert host.mac is None


def test_improved_usage_example():
    """Demonstrate the improved API with convenience properties."""
    xml = DATA_DIR / "1_os_banner_scripts.xml"
    result = NmapRun.from_xml(xml.read_bytes())

    # OLD WAY (still works for backward compatibility):
    # host = result.hosts[0]
    # ports = host.ports.ports
    # state = host.status.state

    # NEW WAY (cleaner and more intuitive):
    host = result.hosts[0]
    ports = host.port_list  # Instead of host.ports.ports
    state = host.state  # Instead of host.status.state

    # Verify both ways produce same results
    assert ports == host.ports.ports
    assert state == host.status.state

    # Access port information more easily
    for port in ports:
        port_state = port.port_state  # Instead of port.state.state
        service = port.service_name  # Instead of port.service.name if port.service else None

        assert port_state == port.state.state
        if port.service:
            assert service == port.service.name

    # Access scan statistics more easily
    total_hosts = result.hosts_total  # Instead of result.stats.hosts["total"]
    hosts_up = result.hosts_up  # Instead of result.stats.hosts["up"]

    assert total_hosts == result.stats.hosts["total"]
    assert hosts_up == result.stats.hosts["up"]
