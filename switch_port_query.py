#!/usr/bin/env python3
"""
Project Title: SwitchPortQuery

A CLI tool to retrieve switchport status across multiple devices and search specific switchport entries,
with both command-line and interactive modes.

Author: Kris Sales
"""
__version__ = "1.1.0"

from __future__ import annotations

import argparse
import logging
import sys
import re
from logging.handlers import RotatingFileHandler
from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
)

# SNMP status mapping
_STATUS_MAP: dict[int, str] = {
    1: "up",
    2: "down",
    3: "testing",
}

def setup_logging(verbose: bool, logfile: str) -> None:
    """
    Configure root logger with a rotating file handler.

    Args:
        verbose: If True, set logging level to DEBUG, else INFO.
        logfile: Path to the log file.
    """
    level = logging.DEBUG if verbose else logging.INFO
    handler = RotatingFileHandler(logfile, maxBytes=1_000_000, backupCount=3)
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    )
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)

def get_num_interfaces(engine: SnmpEngine, target_ip: str, community: str) -> int:
    """
    Retrieve the number of interfaces via SNMP IF-MIB.ifNumber.

    Args:
        engine: Cached SnmpEngine instance.
        target_ip: IP address of the target device.
        community: SNMP community string.

    Returns:
        Number of interfaces.

    Raises:
        ConnectionError: On SNMP connection issues.
        TimeoutError: On SNMP timeout.
        RuntimeError: On other SNMP errors.
    """
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(
            engine,
            CommunityData(community),
            UdpTransportTarget((target_ip, 161), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('IF-MIB', 'ifNumber')),
        )
    )
    if errorIndication:
        if "timeout" in str(errorIndication).lower():
            raise TimeoutError(f"SNMP timeout for {target_ip}")
        raise ConnectionError(f"SNMP connection error: {errorIndication}")
    if errorStatus:
        raise RuntimeError(
            f"SNMP error: {errorStatus.prettyPrint()} at var {errorIndex}"
        )
    return int(varBinds[0][1])

def get_interface_status(
    engine: SnmpEngine,
    target_ip: str,
    community: str,
    interface_index: int,
) -> tuple[str, str]:
    """
    Retrieve admin and oper status for a given interface index.

    Args:
        engine: Cached SnmpEngine instance.
        target_ip: IP address of the target device.
        community: SNMP community string.
        interface_index: Interface index to query.

    Returns:
        Tuple (admin_status, oper_status) as strings.

    Raises:
        ConnectionError: On SNMP connection issues.
        TimeoutError: On SNMP timeout.
        RuntimeError: On other SNMP errors.
    """
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(
            engine,
            CommunityData(community),
            UdpTransportTarget((target_ip, 161), timeout=2, retries=1),
            ContextData(),
            ObjectType(
                ObjectIdentity('IF-MIB', 'ifAdminStatus', interface_index)
            ),
            ObjectType(
                ObjectIdentity('IF-MIB', 'ifOperStatus', interface_index)
            ),
        )
    )
    if errorIndication:
        if "timeout" in str(errorIndication).lower():
            raise TimeoutError(f"SNMP timeout for {target_ip}")
        raise ConnectionError(f"SNMP connection error: {errorIndication}")
    if errorStatus:
        raise RuntimeError(
            f"SNMP error: {errorStatus.prettyPrint()} at var {errorIndex}"
        )
    admin_val = int(varBinds[0][1])
    oper_val = int(varBinds[1][1])
    admin_str = _STATUS_MAP.get(admin_val, str(admin_val))
    oper_str = _STATUS_MAP.get(oper_val, str(oper_val))
    return admin_str, oper_str

def cmd_status(args: argparse.Namespace) -> int:
    """
    Handle the 'status' subcommand: query each host via SNMP.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    logger = logging.getLogger(__name__)
    engine = SnmpEngine()
    for host in args.hosts:
        logger.info("Querying host %s", host)
        try:
            count = get_num_interfaces(engine, host, args.username)
        except (ConnectionError, TimeoutError) as e:
            logger.error("Failed to connect to %s: %s", host, e)
            continue
        except RuntimeError as e:
            logger.error("Failed to get interface count for %s: %s", host, e)
            continue
        print(f"Host: {host} ({count} interfaces)")
        for idx in range(1, count + 1):
            try:
                admin, oper = get_interface_status(engine, host, args.username, idx)
                print(f"  Interface {idx}: Admin={admin}, Oper={oper}")
            except (ConnectionError, TimeoutError) as e:
                logger.error("Failed to connect for %s interface %d: %s", host, idx, e)
            except RuntimeError as e:
                logger.error("Error retrieving status for %s interface %d: %s", host, idx, e)
    return 0

def cmd_find(args: argparse.Namespace) -> int:
    """
    Handle the 'find' subcommand: search within a switchport output file.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    logger = logging.getLogger(__name__)
    try:
        with open(args.input_file, encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        logger.error("Input file not found: %s", args.input_file)
        return 1
    except PermissionError:
        logger.error("Permission denied for file: %s", args.input_file)
        return 1
    print(f"Searching for '{args.search}' in {args.input_file}...")
    matches = [line.rstrip() for line in lines if args.search in line]
    if not matches:
        print("No matches found.")
    else:
        for m in matches:
            print(m)
    return 0

def interactive_mode(verbose: bool, logfile: str) -> argparse.Namespace:
    """
    Launch an interactive prompt to collect command and arguments.

    Args:
        verbose: If True, enable debug logging.
        logfile: Path to the log file.

    Returns:
        Namespace with parsed arguments.
    """
    print("\n*** Entering Interactive Mode ***")
    cmd: str | None = None
    while cmd not in ("status", "find"):
        cmd = input("Choose command ('status' or 'find'): ").strip().lower()
        if not cmd:
            print("Command cannot be empty.")
    if cmd == "status":
        hosts_input = input("Enter host IPs or hostnames (space-separated): ").strip()
        if not hosts_input:
            print("Hosts cannot be empty. Using default: 127.0.0.1")
            hosts = ["127.0.0.1"]
        else:
            hosts = hosts_input.split()
            # Validate IP/hostname format
            ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[a-zA-Z0-9.-]+$")
            hosts = [h for h in hosts if ip_pattern.match(h)]
            if not hosts:
                print("No valid IPs/hostnames. Using default: 127.0.0.1")
                hosts = ["127.0.0.1"]
        community = input("SNMP community string [public]: ").strip() or "public"
        return argparse.Namespace(
            command="status",
            hosts=hosts,
            username=community,
            verbose=verbose,
            logfile=logfile,
        )
    infile = input("Enter path to switchport output file: ").strip()
    if not infile:
        print("Input file cannot be empty.")
        infile = "output.txt"
    search = input("Enter search term or port identifier: ").strip()
    if not search:
        print("Search term cannot be empty.")
        search = "Gi1/0/1"
    return argparse.Namespace(
        command="find",
        input_file=infile,
        search=search,
        verbose=verbose,
        logfile=logfile,
    )

def main() -> None:
    """
    Parse command-line arguments or launch interactive mode, then dispatch.

    Raises:
        KeyboardInterrupt: Handled gracefully with cleanup.
        Exception: Logged as fatal error with exit code 1.
    """
    parser = argparse.ArgumentParser(
        description="SwitchPortQuery CLI: 'status' and 'find' operations"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging"
    )
    parser.add_argument(
        "--logfile",
        default="switch_port_query.log",
        help="Path to log file (default: switch_port_query.log)"
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Enable interactive prompt mode"
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = False

    # 'status' subcommand
    parser_status = subparsers.add_parser(
        "status",
        help="Retrieve switchport status from devices"
    )
    parser_status.add_argument(
        "--hosts",
        nargs="+",
        required=False,
        help="List of host IPs or hostnames to query"
    )
    parser_status.add_argument(
        "--username",
        help="SNMP community string (default 'public')",
        default="public"
    )
    parser_status.set_defaults(func=cmd_status)

    # 'find' subcommand
    parser_find = subparsers.add_parser(
        "find",
        help="Find specific switchport entries"
    )
    parser_find.add_argument(
        "--input-file",
        help="Path to switchport output file",
        required=False
    )
    parser_find.add_argument(
        "--search",
        help="Search term or port identifier to find",
        required=False
    )
    parser_find.set_defaults(func=cmd_find)

    args, _ = parser.parse_known_args()
    if args.interactive:
        args = interactive_mode(args.verbose, args.logfile)
    setup_logging(args.verbose, args.logfile)
    logger = logging.getLogger(__name__)
    try:
        exit_code = args.func(args)  # type: ignore
    except KeyboardInterrupt:
        logger.info("Cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error("Fatal error: %s", e, exc_info=args.verbose)
        sys.exit(1)
    else:
        sys.exit(exit_code)

if __name__ == "__main__":
    main()