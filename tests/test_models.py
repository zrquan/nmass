from pathlib import Path

import pytest

from nmass.models import CPE, NmapRun


@pytest.fixture
def xml_files() -> dict[str, Path]:
    return {p.name: p for p in Path("tests/data").glob("**/*.xml")}


@pytest.fixture
def cpes() -> list[str]:
    return [
        "cpe:/a:apache:http_server:2.2.22",
        "cpe:/a:heimdal:kerberos",
        "cpe:/a:openbsd:openssh:5.9p1",
        "cpe:/o:apple:iphone_os:5",
        "cpe:/o:apple:mac_os_x:10.8",
        "cpe:/o:apple:mac_os_x",
        "cpe:/o:linux:linux_kernel:2.6.13",
        "cpe:/o:linux:linux_kernel",
        "cpe:/o:microsoft:windows_7",
        "cpe:/o:microsoft:windows_7::-:professional",
        "cpe:/o:microsoft:windows_7::sp1",
        "cpe:/o:microsoft:windows",
        "cpe:/o:microsoft:windows_server_2008::beta3",
        "cpe:/o:microsoft:windows_server_2008",
        "cpe:/o:microsoft:windows_server_2008::sp1",
        "cpe:/o:microsoft:windows_vista::-",
        "cpe:/o:microsoft:windows_vista::sp1",
        "cpe:/o:microsoft:windows_vista::sp2",
    ]


def test_parse_xml_without_errors(xml_files):
    for path in xml_files.values():
        try:
            with open(path) as file:
                nr = NmapRun.from_xml(file.read())
                assert nr.scanner in ("nmap", "masscan")
                print(f"✔ {path}")
        except Exception as err:
            pytest.fail(f"✘ {path} => {err}")


def test_cpe_model(cpes):
    for c in cpes:
        assert CPE(c).part in ("/a", "/o")

    apache = CPE(cpes[0])
    assert apache.part == "/a"
    assert apache.vendor == "apache"
    assert apache.product == "http_server"

    win = CPE(cpes[12])
    assert win.vendor == "microsoft"
    assert win.product == "windows_server_2008"
    assert win.version == ""
    assert win.update == "beta3"
    assert win.edition == ""
    assert win.language == ""

    full_cpe = "cpe:/a:mozilla:firefox:2.0::osx:es-es"
    model = CPE(full_cpe)
    assert (
        model.root == full_cpe
        and model.part == "/a"
        and model.vendor == "mozilla"
        and model.product == "firefox"
        and model.version == "2.0"
        and model.update == ""
        and model.edition == "osx"
        and model.language == "es-es"
    )
