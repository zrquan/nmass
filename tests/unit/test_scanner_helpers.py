"""Tests for Scanner helper methods."""

import subprocess
from unittest.mock import Mock

import pytest

from nmass import Nmap


def test_read_and_process_line_xml_stdout():
    """Test _read_and_process_line correctly processes XML from stdout."""
    nmap = Nmap()
    xml_output = bytearray()

    line = b'<host starttime="1234567890">\n'
    nmap._read_and_process_line(line, is_stdout=True, xml_output=xml_output)

    assert xml_output == line


def test_read_and_process_line_non_xml_stdout():
    """Test _read_and_process_line ignores non-XML from stdout."""
    nmap = Nmap()
    xml_output = bytearray()

    line = b"Some non-XML output\n"
    nmap._read_and_process_line(line, is_stdout=True, xml_output=xml_output)

    assert xml_output == b""


def test_read_and_process_line_stderr():
    """Test _read_and_process_line ignores stderr even if XML-like."""
    nmap = Nmap()
    xml_output = bytearray()

    line = b"<some_xml_tag>\n"
    nmap._read_and_process_line(line, is_stdout=False, xml_output=xml_output)

    assert xml_output == b""


def test_read_and_process_line_warning():
    """Test _read_and_process_line handles warning events."""
    nmap = Nmap()
    xml_output = bytearray()

    # Mock logger to verify warning is logged
    nmap.logger.warning = Mock()

    line = b"Warning: Something went wrong\n"
    nmap._read_and_process_line(line, is_stdout=False, xml_output=xml_output)

    # Warning should be logged
    nmap.logger.warning.assert_called_once()
    assert xml_output == b""


def test_check_timeout_no_timeout():
    """Test _check_timeout with no timeout set."""
    nmap = Nmap()

    # Should not raise with timeout=None
    nmap._check_timeout(start_time=0, timeout=None, cmd=["nmap"])


def test_check_timeout_within_limit():
    """Test _check_timeout when within timeout limit."""
    nmap = Nmap()
    from time import monotonic

    start_time = monotonic()
    # Should not raise when within timeout
    nmap._check_timeout(start_time=start_time, timeout=10.0, cmd=["nmap"])


def test_check_timeout_exceeded():
    """Test _check_timeout raises when timeout exceeded."""
    nmap = Nmap()

    # Set start time to 100 seconds ago
    start_time = 0

    with pytest.raises(subprocess.TimeoutExpired):
        nmap._check_timeout(start_time=start_time, timeout=1.0, cmd=["nmap"])


def test_finalize_result():
    """Test _finalize_result parses XML and runs callbacks."""
    nmap = Nmap()

    # Sample minimal XML
    xml_output = b'<?xml version="1.0"?><nmaprun scanner="nmap" version="7.80" xmloutputversion="1.04"></nmaprun>'

    callback = Mock()
    nmap.with_callbacks(callback)

    result = nmap._finalize_result(xml_output)

    # Result should be parsed
    assert result is not None
    # Callback should be called
    callback.assert_called_once_with(result)


def test_finalize_result_callback_exception():
    """Test _finalize_result isolates callback exceptions."""
    nmap = Nmap()

    xml_output = b'<?xml version="1.0"?><nmaprun scanner="nmap" version="7.80" xmloutputversion="1.04"></nmaprun>'

    def bad_callback(result):
        raise ValueError("Test exception")

    good_callback = Mock()

    nmap.with_callbacks(bad_callback, good_callback)

    # Should not raise despite bad callback
    result = nmap._finalize_result(xml_output)

    # Good callback should still be called
    good_callback.assert_called_once_with(result)


def test_terminate_process_none():
    """Test _terminate_process handles None process."""
    nmap = Nmap()

    # Should not raise
    nmap._terminate_process(None)


def test_terminate_process_already_terminated():
    """Test _terminate_process handles already terminated process."""
    nmap = Nmap()

    proc = Mock(spec=subprocess.Popen)
    proc.poll.return_value = 0  # Already terminated

    nmap._terminate_process(proc)

    # Should not call terminate on already-dead process
    proc.terminate.assert_not_called()


def test_terminate_process_graceful():
    """Test _terminate_process gracefully terminates."""
    nmap = Nmap()

    proc = Mock(spec=subprocess.Popen)
    proc.poll.return_value = None  # Still running
    proc.stdout = Mock()
    proc.stderr = Mock()

    nmap._terminate_process(proc)

    # Should call terminate and wait
    proc.terminate.assert_called_once()
    proc.wait.assert_called_once_with(timeout=5)
    # Should close streams
    proc.stdout.close.assert_called_once()
    proc.stderr.close.assert_called_once()


def test_terminate_process_kill_on_timeout():
    """Test _terminate_process kills if terminate times out."""
    nmap = Nmap()

    proc = Mock(spec=subprocess.Popen)
    proc.poll.return_value = None  # Still running
    proc.wait.side_effect = [subprocess.TimeoutExpired(["nmap"], 5), None]  # First wait times out, second succeeds
    proc.stdout = Mock()
    proc.stderr = Mock()

    nmap._terminate_process(proc)

    # Should call terminate, then kill after timeout
    proc.terminate.assert_called_once()
    proc.kill.assert_called_once()
    # wait should be called twice (after terminate and after kill)
    assert proc.wait.call_count == 2


def test_read_streams_select_eof_removal():
    """Test _read_streams_select removes streams that return EOF (b'')."""
    nmap = Nmap()

    # Mock process
    proc = Mock(spec=subprocess.Popen)

    # Create mock streams
    stream1 = Mock()
    stream1.readline.return_value = b"<host>\n"  # Active stream with data

    stream2 = Mock()
    stream2.readline.return_value = b""  # Exhausted stream (EOF)

    stream3 = Mock()
    stream3.readline.return_value = b"Warning: test\n"  # Active stream with data

    proc.stdout = stream1
    proc.stderr = stream2

    streams = [stream1, stream2, stream3]
    xml_output = bytearray()

    # Mock select.select to return all streams as ready
    import select as select_module

    original_select = select_module.select

    def mock_select(rlist, wlist, xlist, timeout):
        return (streams, [], [])

    select_module.select = mock_select

    try:
        # Call _read_streams_select
        active_streams = nmap._read_streams_select(streams, xml_output, proc, timeout_remaining=None)

        # stream2 (EOF) should be removed, stream1 and stream3 should remain
        assert stream1 in active_streams
        assert stream2 not in active_streams
        assert stream3 in active_streams
        assert len(active_streams) == 2

        # XML should be accumulated from stream1 (which is stdout)
        assert b"<host>\n" in xml_output

    finally:
        # Restore original select
        select_module.select = original_select


def test_read_streams_select_timeout_remaining():
    """Test _read_streams_select uses min(0.1, timeout_remaining) for select timeout."""
    nmap = Nmap()

    proc = Mock(spec=subprocess.Popen)
    stream = Mock()
    stream.readline.return_value = b""  # EOF
    proc.stdout = stream

    streams = [stream]
    xml_output = bytearray()

    import select as select_module

    original_select = select_module.select

    captured_timeout = None

    def mock_select(rlist, wlist, xlist, timeout):
        nonlocal captured_timeout
        captured_timeout = timeout
        return ([], [], [])

    select_module.select = mock_select

    try:
        # Test with large timeout_remaining
        nmap._read_streams_select(streams, xml_output, proc, timeout_remaining=10.0)
        assert captured_timeout == 0.1

        # Test with small timeout_remaining
        nmap._read_streams_select(streams, xml_output, proc, timeout_remaining=0.05)
        assert captured_timeout == 0.05

        # Test with None timeout_remaining
        nmap._read_streams_select(streams, xml_output, proc, timeout_remaining=None)
        assert captured_timeout == 0.1

    finally:
        select_module.select = original_select
