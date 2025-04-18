#!/usr/bin/env python3
"""
Test suite for SwitchPortQuery CLI.

Tests CLI commands, SNMP functions, and edge cases.
"""
import pytest
import os
from unittest.mock import patch, MagicMock
from switch_port_query import (
    setup_logging,
    get_num_interfaces,
    get_interface_status,
    cmd_status,
    cmd_find,
    interactive_mode,
    main,
)
import argparse
import logging


@pytest.fixture
def log_file(tmp_path):
    """Create a temporary log file."""
    return str(tmp_path / "test.log")


@pytest.fixture
def mock_snmp():
    """Mock SNMP getCmd function."""
    with patch("switch_port_query.getCmd") as mock:
        yield mock


def test_setup_logging(log_file):
    """Test logging configuration."""
    setup_logging(verbose=True, logfile=log_file)
    logger = logging.getLogger()
    assert logger.level == logging.DEBUG
    assert any(isinstance(h, logging.handlers.RotatingFileHandler) for h in logger.handlers)
    assert os.path.exists(log_file)


def test_get_num_interfaces(mock_snmp):
    """Test retrieving number of interfaces."""
    mock_snmp.return_value = iter([(
        None, None, None, [(ObjectIdentity('IF-MIB', 'ifNumber'), 5)]
    )])
    engine = MagicMock()
    assert get_num_interfaces(engine, "127.0.0.1", "public") == 5


def test_get_num_interfaces_timeout(mock_snmp):
    """Test SNMP timeout handling."""
    mock_snmp.return_value = iter([(MagicMock(lower=lambda: "timeout"), None, None, [])])
    engine = MagicMock()
    with pytest.raises(TimeoutError):
        get_num_interfaces(engine, "127.0.0.1", "public")


def test_get_interface_status(mock_snmp):
    """Test retrieving interface status."""
    mock_snmp.return_value = iter([(
        None, None, None, [
            (ObjectIdentity('IF-MIB', 'ifAdminStatus', 1), 1),
            (ObjectIdentity('IF-MIB', 'ifOperStatus', 1), 2),
        ]
    )])
    engine = MagicMock()
    admin, oper = get_interface_status(engine, "127.0.0.1", "public", 1)
    assert admin == "up"
    assert oper == "down"


def test_cmd_status(capsys, log_file):
    """Test status command."""
    args = argparse.Namespace(hosts=["127.0.0.1"], username="public", verbose=False, logfile=log_file)
    with patch("switch_port_query.get_num_interfaces", return_value=2):
        with patch("switch_port_query.get_interface_status", return_value=("up", "down")):
            cmd_status(args)
            captured = capsys.readouterr()
            assert "Host: 127.0.0.1 (2 interfaces)" in captured.out
            assert "Interface 1: Admin=up, Oper=down" in captured.out


def test_cmd_find(capsys, tmp_path):
    """Test find command."""
    input_file = tmp_path / "output.txt"
    input_file.write_text("Interface Gi1/0/1: up\nInterface Gi1/0/2: down")
    args = argparse.Namespace(input_file=str(input_file), search="Gi1/0/1", verbose=False, logfile="test.log")
    cmd_find(args)
    captured = capsys.readouterr()
    assert "Interface Gi1/0/1: up" in captured.out
    assert "Interface Gi1/0/2: down" not in captured.out


def test_cmd_find_file_not_found(capsys):
    """Test find command with missing file."""
    args = argparse.Namespace(input_file="nonexistent.txt", search="Gi1/0/1", verbose=False, logfile="test.log")
    exit_code = cmd_find(args)
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "No matches found" not in captured.out


def test_interactive_mode_status(monkeypatch, log_file):
    """Test interactive mode for status command."""
    inputs = iter(["status", "127.0.0.1 10.0.0.1", "public"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    args = interactive_mode(verbose=False, logfile=log_file)
    assert args.command == "status"
    assert args.hosts == ["127.0.0.1", "10.0.0.1"]
    assert args.username == "public"


def test_interactive_mode_find(monkeypatch, log_file):
    """Test interactive mode for find command."""
    inputs = iter(["find", "output.txt", "Gi1/0/1"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    args = interactive_mode(verbose=False, logfile=log_file)
    assert args.command == "find"
    assert args.input_file == "output.txt"
    assert args.search == "Gi1/0/1"


def test_interactive_mode_invalid_ip(monkeypatch, log_file):
    """Test interactive mode with invalid IP."""
    inputs = iter(["status", "invalid_ip", "public"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    args = interactive_mode(verbose=False, logfile=log_file)
    assert args.hosts == ["127.0.0.1"]


def test_main_keyboard_interrupt(monkeypatch, capsys):
    """Test main function with KeyboardInterrupt."""
    monkeypatch.setattr("argparse.ArgumentParser.parse_known_args", lambda: (argparse.Namespace(
        interactive=False, verbose=False, logfile="test.log", command="status", func=lambda x: None
    ), []))
    monkeypatch.setattr("switch_port_query.setup_logging", lambda x, y: None)
    with patch("switch_port_query.sys.exit") as mock_exit:
        with patch("switch_port_query.logging.getLogger") as mock_logger:
            mock_logger.return_value.info = MagicMock()
            monkeypatch.setattr("switch_port_query.cmd_status", lambda x: 1 / 0)  # Simulate exception
            main()
            mock_logger.return_value.info.assert_called_with("Cancelled by user")
            mock_exit.assert_called_with(0)
