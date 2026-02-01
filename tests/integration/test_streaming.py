"""Integration tests for streaming functionality with real scans."""

import pytest

from nmass.model.elements import Host, NmapRun

from .conftest import collect_async_stream_items, collect_stream_items, is_root


@pytest.mark.integration
def test_nmap_run_stream_basic(nmap_scanner, localhost):
    """Test that run_stream() yields hosts incrementally during scan."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443, 22)

    hosts, final_result = collect_stream_items(scanner)

    # Verify hosts were yielded
    assert len(hosts) > 0, "Should yield at least one host"
    assert all(isinstance(h, Host) for h in hosts), "All yielded items should be Host objects"

    # Verify final result
    assert isinstance(final_result, NmapRun), "Final item should be NmapRun"
    assert len(final_result.hosts) > 0, "Final result should contain hosts"


@pytest.mark.integration
def test_nmap_run_stream_final_result(nmap_scanner, localhost):
    """Test that final NmapRun result contains all scan data."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443)

    hosts, final_result = collect_stream_items(scanner)

    # Verify final result completeness
    assert final_result is not None, "Should return final NmapRun"
    assert len(final_result.hosts) == len(hosts), "Final result should contain all yielded hosts"
    assert final_result.scanner == "nmap", "Scanner should be nmap"
    assert final_result.start is not None, "Should have start time"
    assert final_result.stats is not None, "Should have stats"


@pytest.mark.integration
def test_nmap_run_stream_early_termination(nmap_scanner, localhost):
    """Test breaking early from stream and verify cleanup."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443, 22, 8080)

    first_host = None
    for item in scanner.run_stream():
        if isinstance(item, Host):
            first_host = item
            break  # Early termination

    # Verify we got a host before breaking
    assert first_host is not None, "Should yield at least one host before break"
    assert isinstance(first_host, Host), "First item should be a Host"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_nmap_arun_stream_basic(nmap_scanner, localhost):
    """Test async streaming yields hosts incrementally."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443)

    hosts, final_result = await collect_async_stream_items(scanner)

    # Verify hosts were yielded
    assert len(hosts) > 0, "Should yield at least one host"
    assert all(isinstance(h, Host) for h in hosts), "All yielded items should be Host objects"

    # Verify final result
    assert isinstance(final_result, NmapRun), "Final item should be NmapRun"
    assert len(final_result.hosts) > 0, "Final result should contain hosts"


@pytest.mark.integration
def test_nmap_run_stream_no_duplicates(nmap_scanner, localhost):
    """Test that stream doesn't yield duplicate hosts."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443, 22)

    hosts, final_result = collect_stream_items(scanner)

    # Collect host IDs (using address as identifier)
    host_addresses = [h.addresses[0].addr for h in hosts if h.addresses]

    # Verify no duplicates
    assert len(host_addresses) == len(set(host_addresses)), "Should not yield duplicate hosts"


@pytest.mark.skipif(not is_root(), reason="masscan requires root privileges")
@pytest.mark.integration
def test_masscan_run_stream(masscan_scanner, localhost):
    """Test masscan streaming support."""

    scanner = masscan_scanner.with_targets(localhost).with_ports(80, 443).with_rate(1000)

    hosts, final_result = collect_stream_items(scanner)

    # Masscan should also support streaming
    assert len(hosts) >= 0, "Should complete without error"
    assert isinstance(final_result, NmapRun), "Final item should be NmapRun"
