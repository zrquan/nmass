"""Integration tests for error handling."""

import subprocess
from typing import List

import pytest

from nmass.errors import NmapArgumentError
from nmass.scanner import ProgressInfo


@pytest.mark.integration
def test_timeout_handling(nmap_scanner, localhost):
    """Test timeout raises TimeoutExpired and cleans up."""
    # Use very short timeout with service detection (which takes longer)
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443, 22, 8080).with_service_info()

    # Should raise TimeoutExpired with short timeout
    with pytest.raises(subprocess.TimeoutExpired):
        scanner.run(timeout=0.1)


@pytest.mark.integration
def test_invalid_target(nmap_scanner):
    """Test that invalid target raises appropriate error."""
    with pytest.raises(NmapArgumentError):
        nmap_scanner.with_targets("invalid..target..syntax!!")


@pytest.mark.integration
def test_process_cleanup_on_timeout(nmap_scanner, localhost):
    """Test that process is properly cleaned up on timeout."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443).with_service_info()

    try:
        scanner.run(timeout=0.1)
    except subprocess.TimeoutExpired:
        pass  # Expected

    # Process should be terminated/killed, not left running
    # This is verified by the fact that subsequent scans work correctly
    # and don't hang due to previous process still running

    # Run another scan to verify no process interference
    scanner2 = nmap_scanner.with_targets(localhost).with_ports(80)
    result = scanner2.run()
    assert result is not None, "Subsequent scan should work after timeout"


@pytest.mark.integration
def test_callback_exception_isolation(nmap_scanner, localhost):
    """Test that callback errors don't fail the scan."""
    good_calls: List[ProgressInfo] = []

    def bad_callback(info: ProgressInfo):
        raise RuntimeError("Intentional callback error")

    def good_callback(info: ProgressInfo):
        good_calls.append(info)

    scanner = nmap_scanner.with_targets(localhost).with_ports("1-10000").with_service_info()
    scanner.on_progress(bad_callback)
    scanner.on_progress(good_callback)

    # Scan should complete despite callback exception
    result = scanner.run()

    assert result is not None, "Scan should complete despite bad callback"
    assert len(result.hosts) > 0, "Scan should produce results"
    assert len(good_calls) > 0, "Good callback should still be called"


@pytest.mark.integration
def test_streaming_early_break_cleanup(nmap_scanner, localhost):
    """Test that breaking from stream cleans up properly."""
    from nmass.model.elements import Host

    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443, 22)

    # Break early from stream
    for item in scanner.run_stream():
        if isinstance(item, Host):
            break  # Exit early

    # Should be able to run another scan without issues
    scanner2 = nmap_scanner.with_targets(localhost).with_ports(80)
    result = scanner2.run()
    assert result is not None, "Subsequent scan should work after early break"
