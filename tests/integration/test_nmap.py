import pytest


@pytest.mark.integration
def test_http_title(nmap_scanner, web_target):
    result = nmap_scanner.with_targets(web_target).with_ports(443).with_scripts("http-title").run()
    assert result.hosts[0].ports.ports[0].scripts[0].output == "CrawlMaze - Testbed for Web Crawlers."


@pytest.mark.integration
def test_service_info(nmap_scanner, web_target):
    result = nmap_scanner.with_targets(web_target).with_ports(443).with_service_info().run()
    service = result.hosts[0].ports.ports[0].service
    assert service.name == "http"
    assert service.product == "Google httpd"
    assert service.confidence == 10


@pytest.mark.integration
def test_ports(nmap_scanner, web_target):
    result = nmap_scanner.with_targets(web_target).run()
    assert len(result.hosts[0].ports.ports) == 1000


@pytest.mark.integration
@pytest.mark.asyncio
async def test_async_run(nmap_scanner, web_target):
    result = await nmap_scanner.with_targets(web_target).arun()
    assert len(result.hosts[0].ports.ports) == 1000
