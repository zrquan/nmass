import pytest

from nmass.masscan import Masscan

SCANME = "scanme.nmap.org"
CRAWLMAZE_IP4 = "216.239.34.21"
CRAWLMAZE_IP6 = "2001:4860:4802:32::15"


@pytest.fixture
def masscan_bin():
    return Masscan(bin_path="/usr/bin/masscan")


def test_banners(masscan_bin):
    result = masscan_bin.with_targets(SCANME).with_ports(80, 443).with_banners().run()

    for host in result.hosts:
        if host.ports is None or host.ports.ports is None:
            continue
        for port in host.ports.ports:
            if (srv := port.service) and srv.banner:
                if srv.name == "http.server":
                    assert srv.banner == "Apache/2.4.7 (Ubuntu)"
                elif srv.name == "title":
                    assert srv.banner == "Go ahead and ScanMe!"
                else:
                    assert srv.banner.startswith("HTTP/1.1")


@pytest.mark.asyncio
async def test_async_run(masscan_bin):
    result = await masscan_bin.with_targets(CRAWLMAZE_IP4).with_ports(80, 443).arun()
    assert len(result.hosts) > 0
