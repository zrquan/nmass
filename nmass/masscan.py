import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Self

from nmass.errors import MasscanNotInstalledError
from nmass.models import NmapRun
from nmass.utils import as_root


@dataclass
class Masscan:
    _bin_path: str = ""
    _args: list[str] = field(default_factory=lambda: [])

    def __post_init__(self):
        if self._bin_path == "":
            if w := shutil.which("masscan"):
                self._bin_path = w
            else:
                raise MasscanNotInstalledError()

    @as_root
    def run(
        self,
        timeout: float | None = None,
        with_output: bool = True,
    ) -> NmapRun | None:
        """Run masscan command

        :param timeout: timeout for masscan process, defaults to None
        :param with_output: print masscan's output, defaults to True
        :return: NmapRun object or None
        """
        with tempfile.NamedTemporaryFile(delete_on_close=True) as xml_out:
            cmd = [self._bin_path, "-oX", xml_out.name, *self._args]
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    timeout=timeout,
                    capture_output=not with_output,
                )
            except subprocess.TimeoutExpired:
                logging.warn("masscan scanning timeout")
            except subprocess.CalledProcessError as e:
                logging.error(f"masscan's return code is {e.returncode}")
                logging.error(e.stderr.decode())
            except Exception as why:
                logging.exception(why)
            else:
                return NmapRun.from_xml(xml_out.read())

            return None

    def with_targets(self, *targets: list[str]) -> Self:
        self._args.extend(targets)
        return self

    def with_ports(self, *ports: list[int | str]) -> Self:
        if type(ports[0]) is int:
            ports_str = ",".join([str(p) for p in ports])
        else:
            ports_str = ",".join(ports)
        self._args.extend(("--ports", ports_str))
        return self

    def with_rate(self, rate: int) -> Self:
        self._args.extend(("--rate", str(rate)))
        return self

    def with_banner(self) -> Self:
        self._args.append("--banner")
        return self

    def with_config(self, filename: str) -> Self:
        self._args.extend(("-c", filename))
        return self

    # 是否要以 with_ 开头
    def echo_config(self) -> Self:
        self._args.append("--echo")
        return self

    def with_adapter_ip(self, ip: str) -> Self:
        self._args.extend(("--adapter-ip", ip))
        return self

    def with_adapter_mac(self, mac: str) -> Self:
        self._args.extend(("--adapter-mac", mac))
        return self

    def with_router_mac(self, mac: str) -> Self:
        self._args.extend(("--router-mac", mac))
        return self
