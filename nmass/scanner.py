import asyncio
import logging
import subprocess
import tempfile
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Self

from aiofiles import tempfile as atempfile

from nmass.models import Address, NmapRun


@dataclass
class Scanner:
    bin_path: str = ""
    _args: list[str] = field(default_factory=lambda: [], init=False)

    @abstractmethod
    def run(
        self,
        timeout: float | None = None,
        with_output: bool = True,
    ) -> NmapRun | None:
        raise NotImplementedError()

    def _run_command(
        self,
        timeout: float | None = None,
        with_output: bool = True,
    ) -> NmapRun | None:
        with tempfile.NamedTemporaryFile() as xml_out:
            cmd = [self.bin_path, "-oX", xml_out.name, *self._args]
            try:
                subprocess.run(
                    cmd,
                    check=True,
                    timeout=timeout,
                    capture_output=not with_output,
                )
            except subprocess.TimeoutExpired:
                raise
            except subprocess.CalledProcessError as e:
                logging.error(e.stderr.decode())
                raise
            except Exception as why:
                logging.exception(why)
            else:
                return NmapRun.from_xml(xml_out.read())

            return None

    @abstractmethod
    async def arun(
        self,
        timeout: float | None = None,
        with_output: bool = True,
    ) -> NmapRun | None:
        raise NotImplementedError()

    async def _arun_command(
        self,
        timeout: float | None = None,
        with_output: bool = True,
    ) -> NmapRun | None:
        async with atempfile.NamedTemporaryFile() as xml_out:
            proc = await asyncio.create_subprocess_exec(
                self.bin_path,
                *["-oX", xml_out.name, *self._args],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
                # TODO: 运行中实时打印输出
                if with_output:
                    print(stdout.decode())
            except asyncio.TimeoutError:
                raise
            except Exception as why:
                logging.exception(why)
            else:
                if proc.returncode != 0:
                    logging.error(stderr.decode())
                    raise subprocess.CalledProcessError(returncode=proc.returncode)
                else:
                    return NmapRun.from_xml(await xml_out.read())

            return None

    def with_step(self, model: NmapRun) -> Self:
        # masscan 中同一个目标会有多个 host element
        targets = set()
        ports = set()
        for host in model.hosts:
            for addr in host.address:
                match addr:
                    case Address(addr=ipv4, addrtype="ipv4"):
                        targets.add(ipv4)
                    case Address(addr=ipv6, addrtype="ipv6"):
                        self.with_ipv6()
                        targets.add(ipv6)
                    case Address(addr=_, addrtype="mac"):
                        logging.warn("MAC is not support")
            for port in host.ports.ports:
                ports.add(port.portid)
        self.with_targets(*targets)
        self.with_ports(*ports)
        return self

    def with_targets(self, *targets: list[str]) -> Self:
        self._args.extend(targets)
        return self

    def with_ports(self, *ports: list[int | str]) -> Self:
        # 注意 nmap 只有 -p 没有 --ports
        if type(ports[0]) is int:
            ports_str = ",".join([str(p) for p in ports])
        else:
            ports_str = ",".join(ports)

        # 多次调用 with_ports 添加端口
        place = -1
        for i, arg in enumerate(self._args):
            if arg == "-p":
                place = i
                break

        if place > 0:
            if i == len(self._args) - 1:
                self._args.append("")
            else:
                ports_str = self._args[place + 1] + "," + ports_str
            self._args[place + 1] = ports_str
        else:
            self._args.extend(("-p", ports_str))

        return self

    def with_target_input(self, input_filename: str) -> Self:
        self._args.extend(("-iL", input_filename))
        return self

    def with_target_exclusion(self, *targets: list[str]) -> Self:
        self._args.extend(("--exclude", ",".join(targets)))
        return self

    def with_target_exclusion_input(self, input_filename: str) -> Self:
        self._args.extend(("--excludefile", input_filename))
        return self

    def without_closed_ports(self) -> Self:
        pass
