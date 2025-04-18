# SwitchPortQuery

[![Build Status](https://github.com/yourusername/switch-port-query/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/switch-port-query/actions)
[![Coverage](https://img.shields.io/codecov/c/github/yourusername/switch-port-query)](https://codecov.io/gh/yourusername/switch-port-query)
[![PyPI](https://img.shields.io/pypi/v/switch-port-query)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)]()

## Project Summary

`SwitchPortQuery` is a CLI tool to retrieve SNMP switchport status and search through port outputs interactively or via command-line.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### CLI Mode

```bash
python switch_port_query.py status --hosts 10.0.0.1 10.0.0.2 --username public
python switch_port_query.py find --input-file output.txt --search Gi1/0/1
```

### Interactive Mode

```bash
python switch_port_query.py --interactive
```

## Setup GitHub Repository

```bash
git init
git add .
git commit -m "Initial commit: SwitchPortQuery v1.1.0"
git tag v1.1.0
gh repo create switch-port-query --public --source=. --remote=origin
git push origin main --tags
```

## Requirements

- Python 3.9+
- `pysnmp>=4.4,<5.0`
- `pytest>=7.0,<8.0`

## License

Apache License 2.0. See [LICENSE](LICENSE)

## Download

Download the release bundle: [switch_port_query_v1.1.0.zip](https://github.com/yourusername/switch-port-query/releases/download/v1.1.0/switch_port_query_v1.1.0.zip)