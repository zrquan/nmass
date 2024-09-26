import asyncio
import logging
import subprocess
import tempfile
import time
from abc import abstractmethod
from collections.abc import Callable
from typing import Any, Optional, Union

from aiofiles import tempfile as atempfile
from typing_extensions import Self

from nmass.model.elements import NmapRun
from nmass.utils import validate_target


class Scanner:
    def __init__(self, bin_path: str = "") -> None:
        self.bin_path = bin_path
        self._args: list[str] = []
        self._callbacks: list[Callable[[NmapRun], Any]] = []

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self.bin_path} {' '.join(self._args)}]>"

    @abstractmethod
    def run(self, timeout: Optional[float], with_output: bool) -> Optional[NmapRun]:
        raise NotImplementedError()

    def _run_command(self, timeout: Optional[float], with_output: bool) -> Optional[NmapRun]:
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
    async def arun(self, timeout: Optional[float], with_output: bool) -> Optional[NmapRun]:
        raise NotImplementedError()

    async def _arun_command(self, timeout: Optional[float], with_output: bool) -> Optional[NmapRun]:
        async with atempfile.NamedTemporaryFile() as xml_out:
            cmd_args = ["-ox", xml_out.name, *self._args]
            proc = await asyncio.create_subprocess_exec(
                self.bin_path,
                *cmd_args,  # type: ignore
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            if with_output:
                start_time = time.time()
                killed = False
                if proc.stdout:
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
                if proc.returncode and proc.returncode != 0:
                    raise subprocess.CalledProcessError(
                        returncode=proc.returncode,
                        cmd=f"{self.bin_path} {' '.join(cmd_args)}",  # type: ignore
                    )
                else:
                    return NmapRun.from_xml(await xml_out.read())

            return None

    def with_callbacks(self, *callbacks: Callable[[NmapRun], Any]) -> Self:
        self._callbacks.extend(callbacks)
        return self

    def with_custom_args(self, args: str) -> Self:
        for a in args.split(" "):
            if a != "":
                self._args.append(a.strip())
        return self

    def with_targets(self, *targets: str) -> Self:
        for t in targets:
            validate_target(t)
        self._args.extend(targets)
        return self

    def with_ports(self, *ports: Union[int, str]) -> Self:
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
        raise NotImplementedError()
