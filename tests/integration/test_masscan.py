import pytest

from tests.integration.conftest import is_root

CRAWLMAZE_IP4 = "216.239.34.21"


@pytest.mark.skipif(not is_root(), reason="masscan requires root privileges")
@pytest.mark.integration
def test_banners(masscan_scanner, localhost):
    result = masscan_scanner.with_targets(localhost).with_ports(80, 443).with_banners().run()

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


@pytest.mark.skipif(not is_root(), reason="masscan requires root privileges")
@pytest.mark.integration
@pytest.mark.asyncio
async def test_async_run(masscan_scanner):
    result = await masscan_scanner.with_targets(CRAWLMAZE_IP4).with_ports(80, 443).arun()
    assert len(result.hosts) > 0
