import asyncio
import logging
import os
import subprocess
from abc import abstractmethod
from collections.abc import Callable
from typing import Any, TypedDict

from typing_extensions import Self, Unpack

from .model.elements import NmapRun
from .utils import validate_target


class ProcessArgs(TypedDict, total=False):
    preexec_fn: Any
    close_fds: bool
    cwd: str | bytes | os.PathLike
    env: dict[str, str]
    restore_signals: bool
    start_new_session: bool
    user: str
    group: str
    umask: int


class Scanner:
    def __init__(self, bin_path: str = "") -> None:
        self.bin_path = bin_path
        self._args: list[str] = ["-oX", "-"]
        self._callbacks: list[Callable[[NmapRun], Any]] = []

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self.bin_path} {' '.join(self._args)}]>"

    @abstractmethod
    def run(self, timeout: float | None, **kwargs: Unpack[ProcessArgs]) -> NmapRun | None:
        raise NotImplementedError()

    def _run_command(self, timeout: float | None, **kwargs: Unpack[ProcessArgs]) -> NmapRun | None:
        cmd = [self.bin_path, *self._args]
        try:
            # masscan 使用 stderr 来输出扫描状态
            output = subprocess.check_output(cmd, timeout=timeout, stderr=subprocess.DEVNULL, **kwargs)
            result = NmapRun.from_xml(output)
        except subprocess.TimeoutExpired:
            raise
        except subprocess.CalledProcessError as e:
            logging.exception(f"Command failed with error: {e.stderr.decode()}")
            raise
        except Exception as why:
            logging.exception(f"Unexpected error running command: {why}")
        else:
            if self._callbacks:
                for func in self._callbacks:
                    try:
                        func(result)
                    except Exception as why:
                        logging.exception(f"Error running callback function: {why}")
            return result

        return None

    @abstractmethod
    async def arun(self, timeout: float | None, **kwargs: Unpack[ProcessArgs]) -> NmapRun | None:
        raise NotImplementedError()

    async def _arun_command(self, timeout: float | None, **kwargs: Unpack[ProcessArgs]) -> NmapRun | None:
        proc = await asyncio.create_subprocess_exec(
            self.bin_path,
            *self._args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            **kwargs,
        )

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
                    cmd=f"{self.bin_path} {' '.join(self._args)}",
                )
            elif proc.stdout is None:
                return None
            else:
                return NmapRun.from_xml(await proc.stdout.read())

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

    def with_most_common_ports(self, top: int) -> Self:
        """Scan the most common ports (--top-ports).

        :param top: Number of top common ports to scan
        :raises ValueError: If top is not between 1 and 65535
        """
        if not 0 < top <= 65535:
            raise ValueError(f"invalid argument value {top=}, port number should between 1 to 65535")
        self._args.extend(("--top-ports", str(top)))
        return self

    def without_closed_ports(self) -> Self:
        raise NotImplementedError()
