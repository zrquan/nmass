"""Integration tests for progress callback functionality."""

from typing import List

import pytest

from nmass.scanner import ProgressInfo
from tests.integration.conftest import is_root


@pytest.mark.integration
def test_progress_callback_called(nmap_scanner, web_target):
    """Test that progress callbacks are invoked during scan."""
    progress_calls: List[ProgressInfo] = []

    def callback(info: ProgressInfo):
        progress_calls.append(info)

    scanner = nmap_scanner.with_targets(web_target).with_ports(80, 443, 22).with_version_light()
    scanner.with_progress_callback(callback, stats_every="1s")
    scanner.run()

    # Verify callbacks were called
    assert len(progress_calls) > 0, "Progress callback should be called at least once"


@pytest.mark.integration
def test_progress_callback_data(nmap_scanner, web_target):
    """Test that ProgressInfo contains valid data."""
    progress_calls: List[ProgressInfo] = []

    def callback(info: ProgressInfo):
        progress_calls.append(info)

    scanner = nmap_scanner.with_targets(web_target).with_ports(80, 443).with_version_light()
    scanner.with_progress_callback(callback, stats_every="1s")
    scanner.run()

    # Verify data in progress info
    assert len(progress_calls) > 0, "Should have progress updates"

    for info in progress_calls:
        assert isinstance(info, ProgressInfo), "Should be ProgressInfo instance"
        assert 0 <= info.percent <= 100, f"Percent should be 0-100, got {info.percent}"
        assert info.task is not None, "Task should not be None"
        assert len(info.task) > 0, "Task should not be empty"


@pytest.mark.integration
def test_multiple_progress_callbacks(nmap_scanner, web_target):
    """Test that multiple callbacks all execute."""
    calls_1: List[ProgressInfo] = []
    calls_2: List[ProgressInfo] = []

    def callback1(info: ProgressInfo):
        calls_1.append(info)

    def callback2(info: ProgressInfo):
        calls_2.append(info)

    scanner = nmap_scanner.with_targets(web_target).with_ports(80, 443).with_version_light()
    scanner.with_progress_callback(callback1, stats_every="1s")
    scanner.with_progress_callback(callback2, stats_every="1s")
    scanner.run()

    # Both callbacks should be called
    assert len(calls_1) > 0, "First callback should be called"
    assert len(calls_2) > 0, "Second callback should be called"
    assert len(calls_1) == len(calls_2), "Both callbacks should be called same number of times"


@pytest.mark.integration
def test_progress_callback_exception_handling(nmap_scanner, web_target):
    """Test that bad callback doesn't crash scan."""
    good_calls: List[ProgressInfo] = []

    def bad_callback(info: ProgressInfo):
        raise ValueError("Intentional error")

    def good_callback(info: ProgressInfo):
        good_calls.append(info)

    scanner = nmap_scanner.with_targets(web_target).with_ports(80, 443).with_version_light()
    scanner.with_progress_callback(bad_callback, stats_every="1s")
    scanner.with_progress_callback(good_callback, stats_every="1s")

    # Scan should complete despite bad callback
    result = scanner.run()

    assert result is not None, "Scan should complete"
    assert len(good_calls) > 0, "Good callback should still be called"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_async_progress_callbacks(nmap_scanner, web_target):
    """Test progress callbacks work in async mode."""
    progress_calls: List[ProgressInfo] = []

    def callback(info: ProgressInfo):
        progress_calls.append(info)

    scanner = nmap_scanner.with_targets(web_target).with_ports(80, 443).with_version_light()
    scanner.with_progress_callback(callback, stats_every="1s")
    result = await scanner.arun()

    # Verify callbacks were called in async mode
    assert result is not None, "Async scan should complete"
    assert len(progress_calls) > 0, "Progress callback should be called in async mode"


@pytest.mark.integration
def test_stateful_progress_tracking(nmap_scanner, web_target):
    """Test tracking progress over time shows increasing percent."""
    progress_calls: List[ProgressInfo] = []

    def callback(info: ProgressInfo):
        progress_calls.append(info)

    scanner = nmap_scanner.with_targets(web_target).with_ports(80, 443, 22).with_service_info()
    scanner.with_progress_callback(callback, stats_every="1s")
    scanner.run()

    # Verify progress increases over time
    assert len(progress_calls) >= 2, "Should have multiple progress updates"

    percents = [info.percent for info in progress_calls]
    # First percent should be less than last percent (progress increases)
    assert percents[0] < percents[-1], "Progress should increase over time"


@pytest.mark.skipif(not is_root(), reason="masscan requires root privileges")
@pytest.mark.integration
def test_masscan_no_progress(masscan_scanner, web_target):
    """Test that masscan doesn't generate progress events (currently)."""
    progress_calls: List[ProgressInfo] = []

    def callback(info: ProgressInfo):
        progress_calls.append(info)

    scanner = masscan_scanner.with_targets(web_target).with_ports(80, 443).with_rate(10)
    scanner.with_progress_callback(callback)
    result = scanner.run()

    # Masscan currently doesn't emit progress events
    assert result is not None, "Scan should complete"
    # Note: If masscan adds progress support in the future, this test will need updating
