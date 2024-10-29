# Nmass

[![Release](https://img.shields.io/github/v/release/zrquan/nmass)](https://img.shields.io/github/v/release/zrquan/nmass)
[![Build status](https://img.shields.io/github/actions/workflow/status/zrquan/nmass/main.yml?branch=main)](https://github.com/zrquan/nmass/actions/workflows/main.yml?query=branch%3Amain)
[![Commit activity](https://img.shields.io/github/commit-activity/m/zrquan/nmass)](https://img.shields.io/github/commit-activity/m/zrquan/nmass)
[![License](https://img.shields.io/github/license/zrquan/nmass)](https://img.shields.io/github/license/zrquan/nmass)

Nmass is a python3 library that makes it easier for developers to use **nmap and masscan**. It translates many and complex arguments into idiomatic methods and wraps the scan results in well-defined **pydantic** models.

## Examples

### Basic nmap example

```python title="nmap_example.py"
nm = (
    Nmap()
    .with_targets("172.18.0.2")
    .with_most_common_ports(100)
    .with_service_info()
    .with_default_script()
    .without_ping()
    .without_dns_resolution()
)
if result := nm.run(with_output=False):
    print(result.model_dump_json(exclude_none=True))
```

### Basic masscan example

```python title="masscan_example.py"
ms = (
    Masscan()
    .with_targets("183.2.172.185")
    .with_ports("80,443")
    .with_banner()
)
if result := ms.run(with_output=False):
    print(result.model_dump_json(exclude_none=True))
```

### More?

Masscan is fast, and nmap is powerful. Why not combine the two?🤩 Start by using masscan to quickly detect open ports in bulk, then use nmap to perform in-depth scans on these open ports!

```{.python .annotate hl_lines="10"}
step1 = (
    Masscan()
    .with_targets("10.0.0.0/8") # (1)
    .with_ports(80, 443)
    .with_rate(10000)
)
step2 = (
    Nmap()
    .with_step(step1.run())
    .with_service_info()
    .with_scripts("http-title")
    .with_verbose()
)
retult = step2.run()
```

1. This is just an example, is not recommended to run.
