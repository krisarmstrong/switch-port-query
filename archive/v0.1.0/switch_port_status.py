#!/usr/bin/env python3
"""
Project Title: SwitchPortStatus

A CLI tool to retrieve switchport status across multiple devices and to find specific switchport entries,
with both command-line and interactive modes.

Author: Kris Sales
"""
__version__ = "0.1.0"

from __future__ import annotations

import argparse
import logging
import sys
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

def get_num_interfaces(target_ip: str, community: str) -> int:
    """
    Retrieve the number of interfaces via SNMP IF-MIB.ifNumber.

    Raises:
        RuntimeError on SNMP errors.
    """
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((target_ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity('IF-MIB', 'ifNumber')),
        )
    )
    if errorIndication:
        raise RuntimeError(f"SNMP Error: {errorIndication}")
    if errorStatus:
        raise RuntimeError(
            f"SNMP Error: {errorStatus.prettyPrint()} at var {errorIndex}"
        )
    return int(varBinds[0][1])

def get_interface_status(
    target_ip: str,
    community: str,
    interface_index: int,
) -> tuple[str, str]:
    """
    Retrieve admin and oper status for a given interface index.

    Returns:
        Tuple (admin_status, oper_status) as strings.
    """
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((target_ip, 161)),
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
        raise RuntimeError(f"SNMP Error: {errorIndication}")
    if errorStatus:
        raise RuntimeError(
            f"SNMP Error: {errorStatus.prettyPrint()} at var {errorIndex}"
        )
    admin_val = int(varBinds[0][1])
    oper_val = int(varBinds[1][1])
    admin_str = _STATUS_MAP.get(admin_val, str(admin_val))
    oper_str = _STATUS_MAP.get(oper_val, str(oper_val))
    return admin_str, oper_str

def cmd_status(args: argparse.Namespace) -> int:
    """
    Handle the 'status' subcommand: query each host via SNMP.
    """
    logger = logging.getLogger(__name__)
    for host in args.hosts:
        logger.info("Querying host %s", host)
        try:
            count = get_num_interfaces(host, args.username)
        except Exception as e:
            logger.error("Failed to get interface count for %s: %s", host, e)
            continue
        print(f"Host: {host} ({count} interfaces)")
        for idx in range(1, count + 1):
            try:
                admin, oper = get_interface_status(host, args.username, idx)
                print(f"  Interface {idx}: Admin={admin}, Oper={oper}")
            except Exception as e:
                logger.error(
                    "Error retrieving status for %s interface %d: %s", host, idx, e
                )
    return 0

def cmd_find(args: argparse.Namespace) -> int:
    """
    Handle the 'find' subcommand: search within a switchport output file.
    """
    logger = logging.getLogger(__name__)
    try:
        with open(args.input_file, encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        logger.error("Input file not found: %s", args.input_file)
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
    """
    print("\n*** Entering Interactive Mode ***")
    cmd: str | None = None
    while cmd not in ("status", "find"):
        cmd = input("Choose command ('status' or 'find'): ").strip().lower()
    if cmd == "status":
        hosts = input("Enter host IPs or hostnames (space-separated): ").split()
        community = input("SNMP community string [public]: ").strip() or "public"
        return argparse.Namespace(
            command="status",
            hosts=hosts,
            username=community,
            verbose=verbose,
            logfile=logfile,
        )
    infile = input("Enter path to switchport output file: ").strip()
    search = input("Enter search term or port identifier: ").strip()
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
    """
    parser = argparse.ArgumentParser(
        description="SwitchPortStatus CLI: 'status' and 'find' operations"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging"
    )
    parser.add_argument(
        "--logfile",
        default="switch_port_status.log",
        help="Path to log file (default: switch_port_status.log)"
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
