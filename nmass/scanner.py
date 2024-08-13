import asyncio
import logging
import subprocess
import tempfile
import time
from abc import abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Self, Set

from aiofiles import tempfile as atempfile

from nmass.models import Address, NmapRun
from nmass.utils import validate_target


@dataclass
class Scanner:
    bin_path: str = ""
    _args: list[str] = field(default_factory=lambda: [], init=False)
    _callbacks: list[Callable[[NmapRun], Any]] = field(default_factory=lambda: [], init=False)

    @abstractmethod
    def run(self, timeout: float | None, with_output: bool) -> NmapRun | None:
        raise NotImplementedError()

    def _run_command(self, timeout: float | None, with_output: bool) -> NmapRun | None:
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
                logging.error(f"Command failed with error: {e.stderr.decode()}")
                raise
            except Exception as why:
                logging.exception(f"Unexpected error running command: {why}")
            else:
                result = NmapRun.from_xml(xml_out.read())
                if self._callbacks:
                    for f in self._callbacks:
                        # 回调函数对 result 的修改会影响返回结果
                        try:
                            f(result)
                        except Exception as why:
                            logging.error(f"Error running callback function: {why}")
                return result

            return None

    @abstractmethod
    async def arun(self, timeout: float | None, with_output: bool) -> NmapRun | None:
        raise NotImplementedError()

    async def _arun_command(self, timeout: float | None, with_output: bool) -> NmapRun | None:
        async with atempfile.NamedTemporaryFile() as xml_out:
            proc = await asyncio.create_subprocess_exec(
                self.bin_path,
                *["-oX", xml_out.name, *self._args],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            if with_output:
                start_time = time.time()
                killed = False
                async for line in proc.stdout:
                    print(line.decode().rstrip())
                    if killed:
                        continue
                    if timeout and time.time() - start_time > timeout:
                        proc.kill()
                        killed = True
                if killed:
                    raise asyncio.TimeoutError()

            try:
                await asyncio.wait_for(proc.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                raise
            except Exception as why:
                logging.exception(f"Unexpected error running command: {why}")
            else:
                if proc.returncode != 0:
                    raise subprocess.CalledProcessError(returncode=proc.returncode, cmd=proc.args)
                else:
                    return NmapRun.from_xml(await xml_out.read())

            return None

    def with_step(self, model: NmapRun) -> Self:
        # masscan 中同一个目标会有多个 host element
        targets: Set[str] = set()
        ports: Set[int] = set()

        for host in model.hosts:
            self._process_addresses(host.address, targets)
            ports.update(port.portid for port in host.ports.ports)

        self.with_targets(*targets)
        self.with_ports(*ports)
        return self

    def _process_addresses(self, addresses: list[Address], targets: Set[str]) -> None:
        for addr in addresses:
            match addr:
                case Address(addr=ipv4, addrtype="ipv4"):
                    targets.add(ipv4)
                case Address(addr=ipv6, addrtype="ipv6"):
                    self.with_ipv6()
                    targets.add(ipv6)
                case Address(addr=_, addrtype="mac"):
                    logging.warning("MAC address is not supported")

    def with_callbacks(self, *callbacks: Callable[[NmapRun], Any]) -> Self:
        self._callbacks.extend(callbacks)
        return self

    def with_targets(self, *targets: str) -> Self:
        [validate_target(t) for t in targets]
        self._args.extend(targets)
        return self

    def with_ports(self, *ports: int | str) -> Self:
        if not ports:
            raise ValueError("At least one port must be provided.")

        ports_str = ",".join(str(p) for p in ports)
        try:
            place = self._args.index("-p")
            self._args[place + 1] += "," + ports_str
        except ValueError:
            self._args.extend(("-p", ports_str))

        return self

    def with_target_input(self, input_filename: str) -> Self:
        self._args.extend(("-iL", input_filename))
        return self

    def with_target_exclusion(self, *targets: str) -> Self:
        self._args.extend(("--exclude", ",".join(targets)))
        return self

    def with_target_exclusion_input(self, input_filename: str) -> Self:
        self._args.extend(("--excludefile", input_filename))
        return self

    def without_closed_ports(self) -> Self:
        pass
