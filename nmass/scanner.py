import asyncio
import logging
import os
import select
import subprocess
import xml.etree.ElementTree as ET
from abc import abstractmethod
from collections.abc import AsyncGenerator, Callable, Generator
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from time import monotonic
from typing import Any, TypedDict

from typing_extensions import Self, Unpack

from .model.elements import Host, NmapRun
from .utils import validate_target


class Event(str, Enum):
    task_begin = "taskbegin"
    task_end = "taskend"
    task_progress = "taskprogress"
    warning = "warning"
    nsock_info = "nsock_info"
    packet_trace = "packet_trace"
    others = "others"


@dataclass
class ProgressInfo:
    """Progress information for scan."""

    task: str
    percent: float
    time: datetime
    remaining: int | None = None
    etc: str | None = None


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
        self._progress_callbacks: list[Callable[[ProgressInfo], Any]] = []

        # Create logger for this scanner instance
        self.logger = logging.getLogger(f"{self.__class__.__name__}.{id(self)}")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{self.bin_path} {' '.join(self._args)}]>"

    def _process_event(self, line: str) -> tuple[bool, Event]:
        """Process a line of output and determine its type.

        Args:
            line: Line of output from scanner

        Returns:
            Tuple of (is_xml, event_type)
        """
        is_xml = line.startswith("<")
        event = Event.others

        if line.startswith("<taskbegin"):
            event = Event.task_begin
        elif line.startswith("<taskend"):
            event = Event.task_end
        elif line.startswith("<taskprogress"):
            event = Event.task_progress
        elif line.startswith("NSOCK INFO"):
            event = Event.nsock_info
        elif line.startswith("Warning:"):
            event = Event.warning

        return is_xml, event

    def _handle_event(self, line: str, event: Event) -> None:
        """Handle an event from the scanner output.

        Args:
            line: The output line
            event: The event type
        """
        if event is Event.warning:
            self.logger.warning("Scan warning: %s", line.lstrip("Warning: ").strip())
        elif event is Event.nsock_info:
            self.logger.debug("Nsock info: %s", line.strip())
        elif event in (Event.task_begin, Event.task_end, Event.task_progress):
            try:
                progress_data = ET.fromstring(line).attrib
                self.logger.debug("Task event: %s - %s", event.value, progress_data.get("task", "unknown"))

                if event is Event.task_progress:
                    self._handle_progress(progress_data)
            except ET.ParseError as e:
                self.logger.error("Failed to parse progress XML: %s", e)

    def _handle_progress(self, progress_data: dict[str, str]) -> None:
        """Handle progress update and notify callbacks.

        Args:
            progress_data: Progress data from XML attributes
        """
        try:
            progress = ProgressInfo(
                task=progress_data.get("task", "unknown"),
                percent=float(progress_data.get("percent", 0)),
                time=datetime.fromtimestamp(int(progress_data["time"])),
                remaining=int(progress_data["remaining"]) if "remaining" in progress_data else None,
                etc=progress_data.get("etc"),
            )

            self.logger.info("Progress: %s - %.1f%%", progress.task, progress.percent)

            # Notify progress callbacks
            for callback in self._progress_callbacks:
                try:
                    callback(progress)
                except Exception as e:
                    self.logger.error("Progress callback failed: %s", e, exc_info=True)
        except (KeyError, ValueError) as e:
            self.logger.error("Invalid progress data: %s", e)

    def _read_and_process_line(self, line: bytes, is_stdout: bool, xml_output: bytearray) -> None:
        """Process a single line of output: decode, detect events, handle events, accumulate XML.

        Args:
            line: Raw bytes from stream
            is_stdout: True if from stdout, False if from stderr
            xml_output: Bytearray to accumulate XML output
        """
        line_str = line.decode().rstrip()
        is_xml, event = self._process_event(line_str)

        if event != Event.others:
            self._handle_event(line_str, event)

        if is_stdout and is_xml:
            xml_output.extend(line)

    def _check_timeout(self, start_time: float, timeout: float | None, cmd: list[str]) -> None:
        """Check if timeout has been exceeded and raise TimeoutExpired if so.

        Args:
            start_time: Start time from monotonic()
            timeout: Timeout in seconds, or None for no timeout
            cmd: Command list for exception

        Raises:
            subprocess.TimeoutExpired: If timeout exceeded
        """
        if timeout is not None and (monotonic() - start_time) > timeout:
            raise subprocess.TimeoutExpired(cmd, timeout)

    def _finalize_result(self, xml_output: bytes) -> NmapRun:
        """Parse XML and run callbacks with exception isolation.

        Args:
            xml_output: Accumulated XML output

        Returns:
            Parsed NmapRun object
        """
        self.logger.info("Scan completed successfully")
        result = NmapRun.from_xml(xml_output)

        # Run result callbacks with exception isolation
        if self._callbacks:
            for func in self._callbacks:
                try:
                    func(result)
                except Exception as e:
                    self.logger.error("Result callback failed: %s", e, exc_info=True)

        return result

    def _terminate_process(self, proc: subprocess.Popen | None, timeout: float = 5) -> None:
        """Gracefully terminate or forcefully kill process.

        Args:
            proc: Process to terminate, or None
            timeout: Seconds to wait before killing
        """
        if proc is None or proc.poll() is not None:
            return

        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            # Use suppress for double-wait scenarios to avoid ResourceWarning
            import contextlib

            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=1)

        # Close streams to avoid resource warnings
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()

    def _read_streams_select(
        self,
        streams: list,
        xml_output: bytearray,
        proc: subprocess.Popen,
        timeout_remaining: float | None = None,
    ) -> list:
        """Read from ready streams using select() and remove exhausted streams.

        Args:
            streams: List of streams to monitor
            xml_output: Bytearray to accumulate XML output
            proc: Process being monitored
            timeout_remaining: Remaining timeout in seconds, or None

        Returns:
            List of still-active streams (streams that haven't reached EOF)
        """
        # Use min(0.1, timeout_remaining) to avoid blocking indefinitely when timeout is near
        select_timeout = 0.1
        if timeout_remaining is not None:
            select_timeout = min(0.1, timeout_remaining)

        ready, _, _ = select.select(streams, [], [], select_timeout)

        active_streams = streams.copy()

        for stream in ready:
            line = stream.readline()

            # EOF detection: when readline() returns b"", the stream is exhausted
            if not line:
                # Remove exhausted stream from active list
                if stream in active_streams:
                    active_streams.remove(stream)
                continue

            # Process the line
            is_stdout = stream is proc.stdout
            self._read_and_process_line(line, is_stdout, xml_output)

        return active_streams

    @abstractmethod
    def run(self, timeout: float | None = None, **kwargs: Unpack[ProcessArgs]) -> NmapRun:
        raise NotImplementedError()

    def _run_command(self, timeout: float | None = None, **kwargs: Unpack[ProcessArgs]) -> NmapRun:
        """Run scanner command and return parsed results.

        Args:
            timeout: Timeout in seconds
            **kwargs: Process arguments

        Returns:
            Parsed NmapRun object

        Raises:
            subprocess.TimeoutExpired: If scan times out
            subprocess.CalledProcessError: If scan fails
        """
        cmd = [self.bin_path, *self._args]
        self.logger.info("Running command: %s", " ".join(cmd))

        proc = None
        try:
            xml_output = bytearray()
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
            start_time = monotonic()

            streams = [s for s in (proc.stdout, proc.stderr) if s is not None]

            # Main loop - reads streams until process exits and all streams are exhausted
            while True:
                self._check_timeout(start_time, timeout, cmd)
                timeout_remaining = timeout - (monotonic() - start_time) if timeout else None
                streams = self._read_streams_select(streams, xml_output, proc, timeout_remaining)

                # Exit when process has exited and all streams are exhausted
                if proc.poll() is not None and not streams:
                    break

            # Get return code and check for errors
            retcode = proc.returncode if proc.returncode is not None else proc.wait()
            if retcode != 0:
                self.logger.error("Scan failed with return code %d", retcode)
                raise subprocess.CalledProcessError(retcode, cmd)

            return self._finalize_result(bytes(xml_output))

        except subprocess.TimeoutExpired:
            self.logger.warning("Scan timed out after %s seconds", timeout)
            if proc:
                proc.kill()
                proc.wait()
            raise
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            if proc:
                proc.terminate()
                proc.wait()
            raise
        except subprocess.CalledProcessError:
            raise
        except Exception as e:
            self.logger.exception("Unexpected error during scan: %s", e)
            raise
        finally:
            self._terminate_process(proc)

    def run_stream(
        self,
        timeout: float | None = None,
        **kwargs: Unpack[ProcessArgs],
    ) -> Generator[Host | NmapRun, None, NmapRun]:
        """Stream scan results as hosts are discovered.

        Yields Host objects as they're discovered during the scan,
        and yields the complete NmapRun object as the final item while
        also returning it as the generator return value for compatibility.

        Args:
            timeout: Timeout in seconds
            **kwargs: Process arguments

        Yields:
            Host objects as they're discovered, followed by the final NmapRun object

        Raises:
            subprocess.TimeoutExpired: If scan times out
            subprocess.CalledProcessError: If scan fails

        Example:
            >>> scanner = Nmap().with_targets("scanme.nmap.org")
            >>> for item in scanner.run_stream():
            ...     if isinstance(item, Host):
            ...         print(f"Found host: {item.ipv4}")
            ...     else:
            ...         result = item  # Final NmapRun object
        """
        cmd = [self.bin_path, *self._args]
        self.logger.info("Running streaming command: %s", " ".join(cmd))

        proc = None
        try:
            xml_output = bytearray()
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
            start_time = monotonic()

            # Track yielded hosts to avoid duplicates
            yielded_hosts: set[str] = set()

            streams = [s for s in (proc.stdout, proc.stderr) if s is not None]

            # Main loop - reads streams until process exits and all streams are exhausted
            while True:
                self._check_timeout(start_time, timeout, cmd)
                timeout_remaining = timeout - (monotonic() - start_time) if timeout else None
                streams = self._read_streams_select(streams, xml_output, proc, timeout_remaining)

                # Try to parse completed hosts incrementally
                try:
                    if b"</host>" in xml_output:
                        hosts = self._parse_completed_hosts(bytes(xml_output), yielded_hosts)
                        for host in hosts:
                            yield host
                except Exception as e:
                    self.logger.debug("Incremental parse attempt failed: %s", e)

                # Exit when process has exited and all streams are exhausted
                if proc.poll() is not None and not streams:
                    break

            # Get return code and check for errors
            retcode = proc.returncode if proc.returncode is not None else proc.wait()
            if retcode != 0:
                self.logger.error("Scan failed with return code %d", retcode)
                raise subprocess.CalledProcessError(retcode, cmd)

            self.logger.info("Scan completed successfully")
            result = NmapRun.from_xml(bytes(xml_output))

            # Yield any remaining hosts that weren't yielded incrementally
            for host in result.hosts:
                host_key = self._get_host_key(host)
                if host_key not in yielded_hosts:
                    yield host

            # Run result callbacks
            if self._callbacks:
                for func in self._callbacks:
                    try:
                        func(result)
                    except Exception as e:
                        self.logger.error("Result callback failed: %s", e, exc_info=True)

            # Yield final result for consistency with async streaming
            yield result
            return result

        except subprocess.TimeoutExpired:
            self.logger.warning("Scan timed out after %s seconds", timeout)
            if proc:
                proc.kill()
                proc.wait()
            raise
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            if proc:
                proc.terminate()
                proc.wait()
            raise
        except subprocess.CalledProcessError:
            raise
        except Exception as e:
            self.logger.exception("Unexpected error during streaming scan: %s", e)
            raise
        finally:
            self._terminate_process(proc)

    def _parse_completed_hosts(self, xml_data: bytes, yielded_hosts: set[str]) -> list[Host]:
        """Parse completed host elements from XML data.

        Args:
            xml_data: Accumulated XML data
            yielded_hosts: Set of already yielded host keys

        Returns:
            List of newly completed hosts
        """
        hosts = []

        try:
            # Simple approach: find all complete <host>...</host> elements
            xml_str = xml_data.decode()
            start_idx = 0

            while True:
                host_start = xml_str.find("<host ", start_idx)
                if host_start == -1:
                    host_start = xml_str.find("<host>", start_idx)
                    if host_start == -1:
                        break

                host_end = xml_str.find("</host>", host_start)
                if host_end == -1:
                    break

                # Extract complete host element
                host_xml = xml_str[host_start : host_end + 7]

                # Wrap in minimal nmaprun element for parsing
                wrapped_xml = f'<?xml version="1.0"?><nmaprun scanner="nmap" version="0" xmloutputversion="1.0">{host_xml}</nmaprun>'  # noqa: E501

                try:
                    partial_run = NmapRun.from_xml(wrapped_xml.encode())
                    if partial_run.hosts:
                        host = partial_run.hosts[0]
                        host_key = self._get_host_key(host)

                        if host_key not in yielded_hosts:
                            hosts.append(host)
                            yielded_hosts.add(host_key)
                except Exception as e:
                    self.logger.debug("Failed to parse host element: %s", e)

                start_idx = host_end + 7

        except Exception as e:
            self.logger.debug("Failed to parse completed hosts: %s", e)

        return hosts

    def _get_host_key(self, host: Host) -> str:
        """Get unique key for a host.

        Args:
            host: Host object

        Returns:
            Unique string identifier for the host
        """
        if host.addresses:
            return host.addresses[0].addr
        return f"host_{id(host)}"

    async def _aread_streams_async(
        self,
        active_streams: dict[str, asyncio.StreamReader],
        xml_output: bytearray,
        proc: asyncio.subprocess.Process,
        timeout_remaining: float | None = None,
    ) -> dict[str, asyncio.StreamReader]:
        """Read from streams asynchronously and remove exhausted streams.

        This async method maintains parity with the sync _read_streams_select approach.
        It properly detects and removes streams that reach EOF.

        Args:
            active_streams: Dict mapping stream names to StreamReader objects
            xml_output: Bytearray to accumulate XML output
            proc: Async process being monitored
            timeout_remaining: Remaining timeout in seconds, or None

        Returns:
            Dict of still-active streams (streams that haven't reached EOF)
        """
        # Use min(0.1, timeout_remaining) similar to sync version
        read_timeout = 0.1
        if timeout_remaining is not None:
            read_timeout = min(0.1, timeout_remaining)

        new_active_streams = active_streams.copy()

        for stream_name, stream in active_streams.items():
            if stream is None:
                continue

            try:
                # Try to read a line with timeout
                line = await asyncio.wait_for(stream.readline(), timeout=read_timeout)

                # EOF detection: when readline() returns b"", the stream is exhausted
                if not line:
                    # Remove exhausted stream
                    if stream_name in new_active_streams:
                        del new_active_streams[stream_name]
                    continue

                # Process the line
                is_stdout = stream_name == "stdout"
                self._read_and_process_line(line, is_stdout, xml_output)

            except asyncio.TimeoutError:
                # No data available within timeout - stream is still active
                pass

        return new_active_streams

    async def _adrain_remaining_output(
        self,
        active_streams: dict[str, asyncio.StreamReader],
        xml_output: bytearray,
    ) -> None:
        """Drain any remaining buffered data from active streams.

        Args:
            active_streams: Dict of active streams to drain
            xml_output: Bytearray to accumulate XML output
        """
        for stream_name, stream in active_streams.items():
            if stream is None:
                continue

            while True:
                remaining = await stream.readline()
                if not remaining:
                    break

                is_stdout = stream_name == "stdout"
                self._read_and_process_line(remaining, is_stdout, xml_output)

    @abstractmethod
    async def arun(self, timeout: float | None = None, **kwargs: Unpack[ProcessArgs]) -> NmapRun:
        raise NotImplementedError()

    async def _arun_command(self, timeout: float | None = None, **kwargs: Unpack[ProcessArgs]) -> NmapRun:
        """Run scanner command asynchronously and return parsed results.

        Args:
            timeout: Timeout in seconds
            **kwargs: Process arguments

        Returns:
            Parsed NmapRun object

        Raises:
            asyncio.TimeoutError: If scan times out
            subprocess.CalledProcessError: If scan fails
        """
        cmd = [self.bin_path, *self._args]
        self.logger.info("Running async command: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            self.bin_path,
            *self._args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **kwargs,
        )

        try:
            xml_output = bytearray()
            start_time = monotonic()

            # Initialize active streams dict
            active_streams = {"stdout": proc.stdout, "stderr": proc.stderr}

            # Main loop - reads streams until process exits and all streams are exhausted
            while True:
                self._check_timeout(start_time, timeout, cmd)
                timeout_remaining = timeout - (monotonic() - start_time) if timeout else None
                active_streams = await self._aread_streams_async(active_streams, xml_output, proc, timeout_remaining)

                # Exit when process has exited and all streams are exhausted
                if proc.returncode is not None and not active_streams:
                    break

            # Drain any remaining buffered output
            if active_streams:
                await self._adrain_remaining_output(active_streams, xml_output)

            # Get return code and check for errors
            if proc.returncode is None:
                await proc.wait()

            if proc.returncode and proc.returncode != 0:
                self.logger.error("Async scan failed with return code %d", proc.returncode)
                raise subprocess.CalledProcessError(
                    returncode=proc.returncode,
                    cmd=f"{self.bin_path} {' '.join(self._args)}",
                )

            return self._finalize_result(bytes(xml_output))

        except subprocess.TimeoutExpired:
            self.logger.warning("Async scan timed out after %s seconds", timeout)
            proc.kill()
            await proc.wait()
            raise asyncio.TimeoutError()
        except asyncio.TimeoutError:
            raise
        except subprocess.CalledProcessError:
            raise
        except Exception as e:
            self.logger.exception("Unexpected error during async scan: %s", e)
            raise

    async def arun_stream(
        self,
        timeout: float | None = None,
        **kwargs: Unpack[ProcessArgs],
    ) -> AsyncGenerator[Host | NmapRun, None]:
        """Stream scan results asynchronously as hosts are discovered.

        Yields Host objects as they're discovered during the scan,
        and yields the complete NmapRun object as the final value.

        Args:
            timeout: Timeout in seconds
            **kwargs: Process arguments

        Yields:
            Host objects as they're discovered, followed by the final NmapRun object

        Raises:
            asyncio.TimeoutError: If scan times out
            subprocess.CalledProcessError: If scan fails

        Example:
            >>> scanner = Nmap().with_targets("scanme.nmap.org")
            >>> result = None
            >>> async for item in scanner.arun_stream():
            ...     if isinstance(item, Host):
            ...         print(f"Found host: {item.ipv4}")
            ...     else:
            ...         result = item  # Final NmapRun object
        """
        cmd = [self.bin_path, *self._args]
        self.logger.info("Running async streaming command: %s", " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            self.bin_path,
            *self._args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **kwargs,
        )

        try:
            xml_output = bytearray()
            yielded_hosts: set[str] = set()
            start_time = monotonic()

            # Initialize active streams dict
            active_streams = {"stdout": proc.stdout, "stderr": proc.stderr}

            # Main loop - reads streams until process exits and all streams are exhausted
            while True:
                self._check_timeout(start_time, timeout, cmd)
                timeout_remaining = timeout - (monotonic() - start_time) if timeout else None
                active_streams = await self._aread_streams_async(active_streams, xml_output, proc, timeout_remaining)

                # Try to parse completed hosts incrementally
                try:
                    if b"</host>" in xml_output:
                        hosts = self._parse_completed_hosts(bytes(xml_output), yielded_hosts)
                        for host in hosts:
                            yield host
                except Exception as e:
                    self.logger.debug("Incremental parse attempt failed: %s", e)

                # Exit when process has exited and all streams are exhausted
                if proc.returncode is not None and not active_streams:
                    break

            # Drain any remaining buffered output and parse hosts
            if active_streams:
                await self._adrain_remaining_output(active_streams, xml_output)
                try:
                    if b"</host>" in xml_output:
                        hosts = self._parse_completed_hosts(bytes(xml_output), yielded_hosts)
                        for host in hosts:
                            yield host
                except Exception as e:
                    self.logger.debug("Incremental parse attempt failed: %s", e)

            # Get return code and check for errors
            if proc.returncode is None:
                await proc.wait()

            if proc.returncode and proc.returncode != 0:
                self.logger.error("Async scan failed with return code %d", proc.returncode)
                raise subprocess.CalledProcessError(
                    returncode=proc.returncode,
                    cmd=f"{self.bin_path} {' '.join(self._args)}",
                )

            self.logger.info("Async scan completed successfully")
            result = NmapRun.from_xml(bytes(xml_output))

            # Yield any remaining hosts that weren't yielded incrementally
            for host in result.hosts:
                host_key = self._get_host_key(host)
                if host_key not in yielded_hosts:
                    yield host

            # Run result callbacks
            if self._callbacks:
                for func in self._callbacks:
                    try:
                        func(result)
                    except Exception as e:
                        self.logger.error("Result callback failed: %s", e, exc_info=True)

            # Yield final NmapRun object
            yield result

        except subprocess.TimeoutExpired:
            self.logger.warning("Async scan timed out after %s seconds", timeout)
            proc.kill()
            await proc.wait()
            raise asyncio.TimeoutError()
        except asyncio.TimeoutError:
            raise
        except subprocess.CalledProcessError:
            raise
        except Exception as e:
            self.logger.exception("Unexpected error during async streaming scan: %s", e)
            raise

    def with_callbacks(self, *callbacks: Callable[[NmapRun], Any]) -> Self:
        """Add callbacks to be called when scan completes.

        Args:
            *callbacks: Functions to call with NmapRun result

        Returns:
            Self for method chaining
        """
        self._callbacks.extend(callbacks)
        return self

    def with_progress_callback(self, *callbacks: Callable[[ProgressInfo], Any]) -> Self:
        """Add progress callbacks to be called during scan.

        Args:
            *callbacks: Functions to call with ProgressInfo updates

        Returns:
            Self for method chaining

        Example:
            >>> def progress_handler(progress: ProgressInfo):
            ...     print(f"{progress.task}: {progress.percent:.1f}%")
            >>>
            >>> scanner = Nmap().with_targets("scanme.nmap.org")
            >>> scanner.with_progress_callback(progress_handler)
            >>> result = scanner.run()
        """
        self._progress_callbacks.extend(callbacks)
        return self

    def on_progress(self, *callbacks: Callable[[ProgressInfo], Any]) -> Self:
        """Alias for with_progress_callback for backward compatibility."""
        return self.with_progress_callback(*callbacks)

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
