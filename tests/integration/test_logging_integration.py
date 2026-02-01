"""Integration tests for logging functionality."""

import io
import logging

import pytest


@pytest.mark.integration
def test_no_print_output(nmap_scanner, localhost, capsys):
    """Test that scan produces no print() output."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443)
    scanner.run()

    # Capture stdout/stderr
    captured = capsys.readouterr()

    # Should have no print output (logging goes to logger, not stdout)
    assert captured.out == "", "Should not print to stdout"


@pytest.mark.integration
def test_logger_levels(nmap_scanner, localhost, caplog):
    """Test setting different log levels."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443)

    # Set DEBUG level
    scanner.logger.setLevel(logging.DEBUG)

    with caplog.at_level(logging.DEBUG):
        scanner.run()

    # Should have debug messages
    assert len(caplog.records) > 0, "Should have log messages at DEBUG level"

    # Verify some messages are DEBUG level
    debug_messages = [r for r in caplog.records if r.levelname == "DEBUG"]
    assert len(debug_messages) > 0, "Should have DEBUG level messages"


@pytest.mark.integration
def test_logger_isolation(nmap_scanner, localhost, caplog):
    """Test that multiple scanners have separate loggers."""
    from nmass.nmap import Nmap

    scanner1 = Nmap()
    scanner2 = Nmap()

    # Verify loggers are different instances
    assert scanner1.logger is not scanner2.logger, "Each scanner should have its own logger"

    # Set different log levels
    scanner1.logger.setLevel(logging.DEBUG)
    scanner2.logger.setLevel(logging.ERROR)

    assert scanner1.logger.level == logging.DEBUG, "Scanner1 should be DEBUG"
    assert scanner2.logger.level == logging.ERROR, "Scanner2 should be ERROR"


@pytest.mark.integration
def test_custom_handler(nmap_scanner, localhost):
    """Test adding custom log handler."""
    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443)

    # Add custom handler
    log_stream = io.StringIO()
    handler = logging.StreamHandler(log_stream)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    scanner.logger.addHandler(handler)
    scanner.logger.setLevel(logging.INFO)

    scanner.run()

    # Verify custom handler received messages
    log_output = log_stream.getvalue()
    assert len(log_output) > 0, "Custom handler should receive log messages"


@pytest.mark.integration
def test_logging_in_streaming(nmap_scanner, localhost, caplog):
    """Test that logging works during streaming."""
    from .conftest import collect_stream_items

    scanner = nmap_scanner.with_targets(localhost).with_ports(80, 443)
    scanner.logger.setLevel(logging.DEBUG)

    with caplog.at_level(logging.DEBUG):
        hosts, final_result = collect_stream_items(scanner)

    # Should have log messages during streaming
    assert len(caplog.records) > 0, "Should have log messages during streaming"
    assert len(hosts) > 0, "Should yield hosts"
