"""Integration tests for async functionality."""

import copy
from typing import List

import pytest

from nmass.scanner import ProgressInfo

from .conftest import collect_async_stream_items


@pytest.mark.integration
@pytest.mark.asyncio
async def test_async_basic_scan(nmap_scanner, localhost):
    """Test basic async scan functionality."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443)
    result = await scanner.arun()

    # Verify result
    assert result is not None, "Should return NmapRun"
    assert len(result.hosts) > 0, "Should have at least one host"
    assert result.scanner == "nmap", "Scanner should be nmap"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_async_streaming(nmap_scanner, localhost):
    """Test async streaming yields results incrementally."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443, 22)

    hosts, final_result = await collect_async_stream_items(scanner)

    # Verify streaming worked
    assert len(hosts) > 0, "Should yield hosts"
    assert final_result is not None, "Should return final NmapRun"
    assert len(final_result.hosts) == len(hosts), "Final result should contain all hosts"


# WTF: 在 vscode 跑测试的话 nmap 输出中没有进度信息，但是在命令行跑 pytest 就没问题...
@pytest.mark.integration
@pytest.mark.asyncio
async def test_async_progress_callbacks(nmap_scanner, localhost):
    """Test progress callbacks work in async mode."""
    progress_calls: List[ProgressInfo] = []

    def callback(info: ProgressInfo):
        progress_calls.append(info)

    # 如果扫描时间过短可能不会生成进度信息
    scanner = nmap_scanner.with_targets(localhost).with_ports("1-10000").with_version_light()
    scanner.with_progress_callback(callback, stats_every="1s")
    result = await scanner.arun()

    # Verify callbacks were called
    assert result is not None, "Scan should complete"
    assert len(progress_calls) > 0, "Progress callbacks should be called in async mode"

    # Verify progress data
    for info in progress_calls:
        assert 0 <= info.percent <= 100, f"Percent should be 0-100, got {info.percent}"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_async_error_handling(nmap_scanner):
    """Test errors propagate correctly in async mode."""
    nmap_scanner.bin_path = "/invalid/path/to/nmap"
    scanner = nmap_scanner.with_targets("invalid..target..syntax").with_ports(80)

    # Should raise error for invalid target
    with pytest.raises(Exception):
        await scanner.arun()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_async_vs_sync_parity(nmap_scanner, localhost):
    """Test that async and sync versions produce similar results."""
    nmap_scanner2 = copy.deepcopy(nmap_scanner)
    scanner_sync = nmap_scanner.with_targets(localhost).with_ports(80, 443)
    scanner_async = nmap_scanner2.with_targets(localhost).with_ports(80, 443)

    # Run sync
    result_sync = scanner_sync.run()

    # Run async
    result_async = await scanner_async.arun()

    # Compare results (should be similar, though exact timing may differ)
    assert len(result_sync.hosts) == len(result_async.hosts), "Should scan same number of hosts"
    assert result_sync.scanner == result_async.scanner, "Scanner should be the same"

    # Compare host data
    if len(result_sync.hosts) > 0 and len(result_async.hosts) > 0:
        sync_host = result_sync.hosts[0]
        async_host = result_async.hosts[0]

        # Addresses should match
        if sync_host.addresses and async_host.addresses:
            assert sync_host.addresses[0].addr == async_host.addresses[0].addr, "Addresses should match"
