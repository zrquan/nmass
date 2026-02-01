"""Tests for progress tracking functionality."""

from datetime import datetime
from pathlib import Path
from unittest.mock import Mock

from nmass import Nmap, ProgressInfo

DATA_DIR = Path(__file__).parent / "data"


def test_progress_info_dataclass():
    """Test ProgressInfo dataclass creation."""
    progress = ProgressInfo(
        task="Test Task",
        percent=50.0,
        time=datetime.now(),
        remaining=100,
        etc="2024-01-01 12:00:00",
    )

    assert progress.task == "Test Task"
    assert progress.percent == 50.0
    assert progress.remaining == 100
    assert progress.etc == "2024-01-01 12:00:00"


def test_progress_info_optional_fields():
    """Test ProgressInfo with optional fields omitted."""
    progress = ProgressInfo(task="Test", percent=25.0, time=datetime.now())

    assert progress.task == "Test"
    assert progress.percent == 25.0
    assert progress.remaining is None
    assert progress.etc is None


def test_with_progress_callback():
    """Test adding progress callbacks with with_progress_callback."""
    nmap = Nmap()

    callback1 = Mock()
    callback2 = Mock()

    nmap.with_progress_callback(callback1, callback2)

    assert len(nmap._progress_callbacks) == 2
    assert callback1 in nmap._progress_callbacks
    assert callback2 in nmap._progress_callbacks


def test_with_progress_callback_chaining():
    """Test that with_progress_callback returns self for chaining."""
    nmap = Nmap()
    callback = Mock()

    result = nmap.with_progress_callback(callback)

    assert result is nmap


def test_progress_callback_called():
    """Test that progress callbacks are called during scan."""
    nmap = Nmap()
    callback = Mock()

    nmap.with_progress_callback(callback)

    # Simulate progress event
    progress_xml = '<taskprogress task="Test" time="1234567890" percent="50.0" remaining="100" etc="2024-01-01"/>'
    nmap._handle_event(progress_xml, nmap._process_event(progress_xml)[1])

    # Verify callback was called
    assert callback.called
    assert isinstance(callback.call_args[0][0], ProgressInfo)


def test_progress_callback_receives_correct_data():
    """Test that progress callbacks receive correct ProgressInfo data."""
    nmap = Nmap()
    received_progress = None

    def callback(progress: ProgressInfo):
        nonlocal received_progress
        received_progress = progress

    nmap.with_progress_callback(callback)

    # Simulate progress event
    progress_xml = '<taskprogress task="DNS resolution" time="1234567890" percent="75.5" remaining="50"/>'
    nmap._handle_event(progress_xml, nmap._process_event(progress_xml)[1])

    assert received_progress is not None
    assert received_progress.task == "DNS resolution"
    assert received_progress.percent == 75.5
    assert received_progress.remaining == 50


def test_multiple_progress_callbacks():
    """Test that multiple progress callbacks are all called."""
    nmap = Nmap()

    callback1 = Mock()
    callback2 = Mock()
    callback3 = Mock()

    nmap.with_progress_callback(callback1, callback2, callback3)

    # Simulate progress event
    progress_xml = '<taskprogress task="Test" time="1234567890" percent="50.0"/>'
    nmap._handle_event(progress_xml, nmap._process_event(progress_xml)[1])

    # All callbacks should be called
    assert callback1.called
    assert callback2.called
    assert callback3.called


def test_progress_callback_exception_handling():
    """Test that exceptions in progress callbacks don't crash the scan."""
    nmap = Nmap()

    def bad_callback(progress: ProgressInfo):
        raise ValueError("Test exception")

    good_callback = Mock()

    nmap.with_progress_callback(bad_callback, good_callback)

    # Simulate progress event - should not raise exception
    progress_xml = '<taskprogress task="Test" time="1234567890" percent="50.0"/>'
    nmap._handle_event(progress_xml, nmap._process_event(progress_xml)[1])

    # Good callback should still be called despite bad callback failing
    assert good_callback.called


def test_handle_progress_with_all_fields():
    """Test _handle_progress with all optional fields present."""
    nmap = Nmap()
    callback = Mock()
    nmap.with_progress_callback(callback)

    progress_data = {
        "task": "Port Scanning",
        "time": "1234567890",
        "percent": "80.0",
        "remaining": "60",
        "etc": "2024-01-01 15:00:00",
    }

    nmap._handle_progress(progress_data)

    assert callback.called
    progress = callback.call_args[0][0]
    assert progress.task == "Port Scanning"
    assert progress.percent == 80.0
    assert progress.remaining == 60
    assert progress.etc == "2024-01-01 15:00:00"


def test_handle_progress_with_minimal_fields():
    """Test _handle_progress with only required fields."""
    nmap = Nmap()
    callback = Mock()
    nmap.with_progress_callback(callback)

    progress_data = {
        "task": "Test",
        "time": "1234567890",
        "percent": "25.0",
    }

    nmap._handle_progress(progress_data)

    assert callback.called
    progress = callback.call_args[0][0]
    assert progress.task == "Test"
    assert progress.percent == 25.0
    assert progress.remaining is None
    assert progress.etc is None


def test_handle_progress_invalid_data():
    """Test _handle_progress with invalid data doesn't crash."""
    nmap = Nmap()
    callback = Mock()
    nmap.with_progress_callback(callback)

    # Missing required field 'time'
    progress_data = {
        "task": "Test",
        "percent": "50.0",
    }

    # Should not raise exception
    nmap._handle_progress(progress_data)

    # Callback should not be called with invalid data
    assert not callback.called


def test_handle_progress_invalid_percent():
    """Test _handle_progress with invalid percent value."""
    nmap = Nmap()
    callback = Mock()
    nmap.with_progress_callback(callback)

    progress_data = {
        "task": "Test",
        "time": "1234567890",
        "percent": "not_a_number",
    }

    # Should not raise exception
    nmap._handle_progress(progress_data)

    # Callback should not be called with invalid data
    assert not callback.called


def test_stateful_progress_callback():
    """Test using a stateful progress callback class."""

    class ProgressTracker:
        def __init__(self):
            self.updates = 0
            self.last_percent = 0.0

        def __call__(self, progress: ProgressInfo):
            self.updates += 1
            self.last_percent = progress.percent

    nmap = Nmap()
    tracker = ProgressTracker()
    nmap.with_progress_callback(tracker)

    # Simulate multiple progress events
    for percent in [25.0, 50.0, 75.0, 100.0]:
        progress_xml = f'<taskprogress task="Test" time="1234567890" percent="{percent}"/>'
        nmap._handle_event(progress_xml, nmap._process_event(progress_xml)[1])

    assert tracker.updates == 4
    assert tracker.last_percent == 100.0
