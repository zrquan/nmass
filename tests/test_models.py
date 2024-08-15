from pathlib import Path

import pytest

from nmass.models import NmapRun


@pytest.fixture
def xml_files() -> list[Path]:
    return list(Path("tests/data").glob("**/*.xml"))


def test_parse_xml_without_errors(xml_files):
    for filename in xml_files:
        try:
            with open(filename) as file:
                nr = NmapRun.from_xml(file.read())
                assert nr.scanner in ("nmap", "masscan")
                print(f"✔ {filename}")
        except Exception as err:
            pytest.fail(f"✘ {filename} => {err}")
