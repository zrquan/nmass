import pytest

from nmass.nmap import Nmap

SCANME = "scanme.nmap.org"
CRAWLMAZE = "security-crawl-maze.app"


@pytest.fixture
def nmap_bin():
    return Nmap(bin_path="/usr/bin/nmap")


def test_http_title(nmap_bin):
    result = nmap_bin.with_targets(CRAWLMAZE).with_ports(443).with_scripts("http-title").run()
    assert result.hosts[0].ports.ports[0].scripts[0].output == "CrawlMaze - Testbed for Web Crawlers."


def test_service_info(nmap_bin):
    result = nmap_bin.with_targets(CRAWLMAZE).with_ports(443).with_service_info().run()
    service = result.hosts[0].ports.ports[0].service
    assert service.name == "http"
    assert service.product == "Google httpd"
    assert service.confidence == 10


def test_ports(nmap_bin):
    result = nmap_bin.with_targets(SCANME).run()
    assert len(result.hosts[0].ports.ports) == 1000
