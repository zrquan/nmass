"""Shared fixtures and helpers for integration tests."""

import ctypes
import os
import sys
from pathlib import Path

import pytest

from nmass.masscan import Masscan
from nmass.model.elements import Host, NmapRun
from nmass.nmap import Nmap


@pytest.fixture
def localhost():
    """Primary test target."""
    return "127.0.0.1"


@pytest.fixture
def web_target():
    """Web application test target."""
    return "security-crawl-maze.app"


@pytest.fixture
def nmap_bin():
    """Path to nmap binary."""
    return "/usr/bin/nmap"


@pytest.fixture
def masscan_bin():
    """Path to masscan binary."""
    return "/usr/bin/masscan"


@pytest.fixture
def nmap_scanner(nmap_bin):
    """Create a fresh Nmap scanner instance."""
    return Nmap(bin_path=nmap_bin)


@pytest.fixture
def masscan_scanner(masscan_bin):
    """Create a fresh Masscan scanner instance."""
    if not masscan_bin or not Path(masscan_bin).exists():
        pytest.skip("masscan not found")
    return Masscan(bin_path=masscan_bin)


def collect_stream_items(scanner):
    """Collect all items from a streaming scan.

    Args:
        scanner: Scanner instance with run_stream() method

    Returns:
        tuple: (list of Host objects, final NmapRun result)
    """
    hosts: list[Host] = []
    final_result: NmapRun | None = None
    gen = scanner.run_stream()
    try:
        while True:
            item = next(gen)
            if isinstance(item, Host):
                hosts.append(item)
            elif isinstance(item, NmapRun):
                final_result = item
    except StopIteration as e:
        # Generator return value is in e.value
        if final_result is None:
            final_result = e.value
    return hosts, final_result


async def collect_async_stream_items(scanner):
    """Collect all items from an async streaming scan.

    Args:
        scanner: Scanner instance with arun_stream() method

    Returns:
        tuple: (list of Host objects, final NmapRun result)
    """
    from nmass.model.elements import NmapRun

    hosts = []
    final_result = None

    async for item in scanner.arun_stream():
        if isinstance(item, Host):
            hosts.append(item)
        elif isinstance(item, NmapRun):
            final_result = item

    return hosts, final_result


def is_root():
    if sys.platform == "win32":
        # Windows OS: Check for administrator privileges
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        # Unix-like OS: Check for root privileges
        return os.getuid() == 0
