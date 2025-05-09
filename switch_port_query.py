#!/usr/bin/env python3
"""
Project Title: SwitchPortQuery

A CLI tool to retrieve switchport status across multiple devices and search specific switchport entries,  # noqa
with both command-line and interactive modes.

Author: Kris Sales
"""
from __future__ import annotations

__version__ = "1.1.0"

import argparse
import logging
import sys
import re
from logging.handlers import RotatingFileHandler

# ─── SNMP IMPORTS ────────────────────────────────────────────────────────────────
try:
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
        ObjectType, ObjectIdentity, getCmd
    )
except ImportError:
    # allow import of cmd_find even if pysnmp is missing
    SnmpEngine = CommunityData = UdpTransportTarget = ContextData = (
        ObjectType, ObjectIdentity, getCmd
    ) = None
# ────────────────────────────────────────────────────────────────────────────────


class Config:
    """Global constants for SwitchPortQuery."""

    STATUS_MAP: dict[int, str] = {
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
    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)


def handle_exceptions(func, args, logger, verbose: bool) -> int:
    """
    Handle exceptions for CLI commands, logging errors and returning appropriate exit codes.

    Args:
        func: The function to execute (cmd_status or cmd_find).
        args: Command-line arguments.
        logger: Logger instance.
        verbose: If True, include traceback in logs.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    try:
        return func(args)
    except KeyboardInterrupt:
        logger.info("Cancelled by user")
        return 0
    except Exception as e:
        logger.error("Fatal error: %s", e, exc_info=verbose)
        return 1


def handle_snmp_error(
        error_indication, error_status, error_index, target_ip: str
) -> None:
    """
    Handle SNMP errors and raise appropriate exceptions.

    Args:
        error_indication: SNMP error indication.
        error_status: SNMP error status.
        error_index: SNMP error index.
        target_ip: Target IP address.

    Raises:
        ConnectionError: On SNMP connection issues.
        TimeoutError: On SNMP timeout.
        RuntimeError: On other SNMP errors.
    """
    if error_indication:
        if "timeout" in str(error_indication).lower():
            raise TimeoutError(f"SNMP timeout for {target_ip}")
        raise ConnectionError(f"SNMP connection error: {error_indication}")
    if error_status:
        raise RuntimeError(
            f"SNMP error: {error_status.prettyPrint()} at var {error_index}"
        )


def snmp_get(
        engine: SnmpEngine, target_ip: str, community: str, *oids: ObjectType
) -> list:
    """
    Perform an SNMP GET request for the given OIDs.

    Args:
        engine: Cached SnmpEngine instance.
        target_ip: IP address of the target device.
        community: SNMP community string.
        oids: ObjectType instances to query.

    Returns:
        List of variable bindings.

    Raises:
        ConnectionError: On SNMP connection issues.
        TimeoutError: On SNMP timeout.
        RuntimeError: On other SNMP errors.
    """
    error_indication, error_status, error_index, var_binds = next(
        getCmd(
            engine,
            CommunityData(community),
            UdpTransportTarget((target_ip, 161), timeout=2, retries=1),
            ContextData(),
            *oids,
        )
    )
    handle_snmp_error(error_indication, error_status, error_index, target_ip)
    return var_binds


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

    
    var_binds = snmp_get(
        engine,
        target_ip,
        community,
        ObjectType(ObjectIdentity("IF-MIB", "ifNumber")),
    )
    return int(var_binds[0][1])


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
    var_binds = snmp_get(
        engine,
        target_ip,
        community,
        ObjectType(ObjectIdentity("IF-MIB", "ifAdminStatus", interface_index)),
        ObjectType(ObjectIdentity("IF-MIB", "ifOperStatus", interface_index)),
    )
    admin_val = int(var_binds[0][1])
    oper_val = int(var_binds[1][1])
    admin_str = Config.STATUS_MAP.get(admin_val, str(admin_val))  # noqa
    oper_str = Config.STATUS_MAP.get(oper_val, str(oper_val))  # noqa
    return admin_str, oper_str


def log_snmp_error(logger, host: str, idx: int | None, e: Exception) -> None:
    """
    Log SNMP errors with context.

    Args:
        logger: Logger instance.
        host: Host IP or hostname.
        idx: Interface index (if applicable, else None).
        e: Exception to log.
    """
    if idx is None:
        logger.error("Failed to connect to %s: %s", host, e)
    else:
        logger.error("Failed to connect for %s interface %d: %s", host, idx, e)


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
            log_snmp_error(logger, host, None, e)
            continue
        except RuntimeError as e:
            logger.error("Failed to get interface count for %s: %s", host, e)
            continue
        print(f"Host: {host} ({count} interfaces)")
        for idx in range(1, count + 1):
            try:
                admin, oper = get_interface_status(engine, host, args.username, idx)
                print(f"  Interface {idx}: Admin={admin}, Oper={oper}")  # noqa
            except (ConnectionError, TimeoutError) as e:
                log_snmp_error(logger, host, idx, e)
            except RuntimeError as e:
                logger.error(
                    "Error retrieving status for %s interface %d: %s", host, idx, e
                )
    return 0


def cmd_find(args: argparse.Namespace) -> int:
    """
    Handle the 'find' subcommand: search within a switchport output file.  # noqa

    Args:
        args: Parsed command-line arguments.

    Returns:
        Exit code (0 for success, 1 for errors).
    """
    logger = logging.getLogger(__name__)
    try:
        with open(args.input_file, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        logger.error("Input file not found: %s", args.input_file)
        return 1
    except PermissionError:
        logger.error("Permission denied for file: %s", args.input_file)
        return 1
    print(f"Searching for '{args.search}' in {args.input_file}...")  # noqa
    matches = [line.rstrip() for line in lines if args.search in line]
    if not matches:
        print("No matches found.")
    else:
        for m in matches:
            print(m)  # noqa
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
    infile = input("Enter path to switchport output file: ").strip()  # noqa
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


def setup_subparser(
        subparsers: argparse._SubParsersAction,  # type: ignore
        name: str,
        help_text: str,
        args: list[tuple[str, dict]],
) -> None:
    """
    Set up a subparser with the given arguments.

    Args:
        subparsers: Subparsers object to add to.
        name: Name of the subcommand.
        help_text: Help text for the subcommand.
        args: List of (flag, kwargs) tuples for arguments.
    """
    parser = subparsers.add_parser(name, help=help_text)
    for flag, kwargs in args:
        parser.add_argument(flag, **kwargs)
    parser.set_defaults(func=globals()[f"cmd_{name}"])


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
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )
    parser.add_argument(
        "--logfile",
        default="switch_port_query.log",
        help="Path to log file (default: switch_port_query.log)",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Enable interactive prompt mode",
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.required = False

    # 'status' subcommand
    setup_subparser(
        subparsers,
        "status",
        "Retrieve switchport status from devices",  # noqa
        [
            (
                "--hosts",
                {
                    "nargs": "+",
                    "required": False,
                    "help": "List of host IPs or hostnames to query",
                },
            ),
            (
                "--username",
                {
                    "help": "SNMP community string (default 'public')",
                    "default": "public",
                },
            ),
        ],
    )

    # 'find' subcommand
    setup_subparser(
        subparsers,
        "find",
        "Find specific switchport entries",  # noqa
        [
            (
                "--input-file",
                {"help": "Path to switchport output file", "required": False},  # noqa
            ),
            (
                "--search",
                {"help": "Search term or port identifier to find", "required": False},
            ),
        ],
    )

    args, _ = parser.parse_known_args()
    if args.interactive:
        args = interactive_mode(args.verbose, args.logfile)
    setup_logging(args.verbose, args.logfile)
    logger = logging.getLogger(__name__)
    exit_code = handle_exceptions(args.func, args, logger, args.verbose)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
