import argparse
from switch_port_status import cmd_find
import pytest

def test_cmd_find_no_matches(tmp_path, capsys):
    file = tmp_path / "out.txt"
    file.write_text("no relevant lines\n")
    args = argparse.Namespace(input_file=str(file), search="foo")
    exit_code = cmd_find(args)
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "No matches found." in captured.out

def test_cmd_find_with_matches(tmp_path, capsys):
    file = tmp_path / "out.txt"
    file.write_text("foo bar\nbaz\nfoo baz\n")
    args = argparse.Namespace(input_file=str(file), search="foo")
    exit_code = cmd_find(args)
    captured = capsys.readouterr()
    assert exit_code == 0
    lines = captured.out.strip().splitlines()
    assert lines[0].startswith("Searching for 'foo'")
    assert "foo bar" in lines
    assert "foo baz" in lines
