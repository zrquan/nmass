"""Integration tests for convenience properties with real scan data."""

import pytest


@pytest.mark.integration
def test_host_properties_real_scan(nmap_scanner, localhost):
    """Test host convenience properties with real scan data."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443, 22).with_service_info()
    result = scanner.run()

    assert len(result.hosts) > 0, "Should have at least one host"
    host = result.hosts[0]

    # Test ip property
    if host.addresses:
        ipv4_addr = next((a for a in host.addresses if a.addrtype == "ipv4"), None)
        if ipv4_addr:
            assert host.ip == ipv4_addr.addr, "ip property should match IPv4 address"

    # Test mac property
    if host.addresses:
        mac_addr = next((a for a in host.addresses if a.addrtype == "mac"), None)
        if mac_addr:
            assert host.mac == mac_addr.addr, "mac property should match MAC address"
        else:
            assert host.mac is None, "mac should be None if no MAC address"

    # Test hostname property
    if host.hostnames:
        assert host.hostname == host.hostnames[0].name, "hostname should match first hostname"
    else:
        assert host.hostname is None, "hostname should be None if no hostnames"

    # Test os_name property
    if host.os and host.os.osmatches:
        assert host.os_name == host.os.osmatches[0].name, "os_name should match first OS match"
    else:
        assert host.os_name is None, "os_name should be None if no OS detection"

    # Test open_ports property
    if host.ports and host.ports.ports:
        open_ports = [p for p in host.ports.ports if p.state and p.state.state == "open"]
        assert host.open_ports == open_ports, "open_ports should match filtered list"


@pytest.mark.integration
def test_port_properties_real_scan(nmap_scanner, web_target):
    """Test port convenience properties with real scan data."""
    scanner = nmap_scanner.with_targets(web_target).with_ports(443).with_service_info().with_scripts("http-title")
    result = scanner.run()

    assert len(result.hosts) > 0, "Should have at least one host"
    host = result.hosts[0]
    assert host.ports and host.ports.ports, "Should have ports"

    port = host.ports.ports[0]

    # Test is_open property
    if port.state:
        expected_open = port.state.state == "open"
        assert port.is_open == expected_open, "is_open should match state"

    # Test service_name property
    if port.service:
        assert port.service_name == port.service.name, "service_name should match service.name"
    else:
        assert port.service_name is None, "service_name should be None if no service"

    # Test service_product property
    if port.service:
        assert port.service_product == port.service.product, "service_product should match service.product"

    # Test service_version property
    if port.service:
        assert port.service_version == port.service.version, "service_version should match service.version"


@pytest.mark.integration
def test_nmaprun_properties_real_scan(nmap_scanner, localhost):
    """Test NmapRun convenience properties with real scan data."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443, 22)
    result = scanner.run()

    # Test up_hosts property
    if result.hosts:
        up_hosts = [h for h in result.hosts if h.status and h.status.state == "up"]
        assert result.up_hosts == up_hosts, "up_hosts should match filtered list"

    # Test down_hosts property
    if result.hosts:
        down_hosts = [h for h in result.hosts if h.status and h.status.state == "down"]
        assert result.down_hosts == down_hosts, "down_hosts should match filtered list"

    # Test total_hosts property
    if result.hosts:
        assert result.total_hosts == len(result.hosts), "total_hosts should match host count"

    # Test scan_stats property
    if result.stats and result.stats.hosts:
        assert result.scan_stats == result.stats.hosts, "scan_stats should match stats.hosts"
    else:
        assert result.scan_stats is None, "scan_stats should be None if no stats"


@pytest.mark.integration
def test_convenience_properties_streaming(nmap_scanner, localhost):
    """Test convenience properties work with streaming."""
    from nmass.model.elements import Host

    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443)

    for item in scanner.run_stream():
        if isinstance(item, Host):
            # Test properties work on streamed hosts
            if item.addresses:
                ipv4_addr = next((a for a in item.addresses if a.addrtype == "ipv4"), None)
                if ipv4_addr:
                    assert item.ip == ipv4_addr.addr, "ip property should work on streamed host"

            if item.ports and item.ports.ports:
                open_ports = [p for p in item.ports.ports if p.state and p.state.state == "open"]
                assert item.open_ports == open_ports, "open_ports should work on streamed host"

            break  # Just test first host
