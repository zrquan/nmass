# Nmass

[![PyPI version](https://badge.fury.io/py/nmass.svg)](https://badge.fury.io/py/nmass) [![](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/) [![](https://img.shields.io/github/license/zrquan/nmass.svg)](https://github.com/zrquan/nmass/blob/main/LICENSE)

Nmass is a python3 library that makes it easier for developers to use **nmap and masscan**. It translates many and complex arguments into idiomatic methods and wraps the scan results in well-defined **pydantic** models.

Docs: https://zrquan.github.io/nmass/

## Features

- Supports all scanning options for both nmap and masscan.
- Supports async execution.
- Complete documentation of each option.
- Convert nmap and masscan scan results into [Pydantic Models](https://docs.pydantic.dev/latest/).
- Convert results to JSON, CSV and HTML.
- Helpful enums and data classes. (timing templates, TCP flags, version info, etc)

## Thanks

- [Ullaakut/nmap](https://github.com/Ullaakut/nmap) - Provided design inspiration.
- [savon-noir/python-libnmap](https://github.com/savon-noir/python-libnmap) - Provided test data.
