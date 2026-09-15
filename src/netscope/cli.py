"""Command-line interface for NetScope."""

from __future__ import annotations

import argparse
import json

from . import __version__
from .diagnostics import check_tcp, inspect_interfaces, resolve_hostname, summarize_tcp
from .reporting import to_csv


def _add_output_options(parser: argparse.ArgumentParser) -> None:
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", dest="as_json", help="Emit machine-readable JSON")
    output.add_argument("--csv", action="store_true", dest="as_csv", help="Emit a one-record CSV report")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Defensive network visibility and diagnostics")
    parser.add_argument("--version", action="version", version=f"NetScope {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    interfaces = subparsers.add_parser("interfaces", help="Inspect local interfaces and host addresses")
    _add_output_options(interfaces)

    dns = subparsers.add_parser("dns", help="Resolve a hostname with the system DNS resolver")
    dns.add_argument("hostname")
    _add_output_options(dns)

    tcp = subparsers.add_parser("tcp", help="Test one explicit TCP host and port")
    tcp.add_argument("host")
    tcp.add_argument("port", type=int)
    tcp.add_argument("--timeout", type=float, default=3.0, help="Connection timeout in seconds (max 30)")
    _add_output_options(tcp)

    summary = subparsers.add_parser("tcp-summary", help="Summarize bounded latency checks for one endpoint")
    summary.add_argument("host")
    summary.add_argument("port", type=int)
    summary.add_argument("--count", type=int, default=3, help="Connection attempts (1-10, default 3)")
    summary.add_argument("--timeout", type=float, default=3.0, help="Per-attempt timeout in seconds (max 30)")
    _add_output_options(summary)
    return parser


def _emit_structured(result: object, args: argparse.Namespace) -> bool:
    if args.as_json:
        print(json.dumps(result.to_dict(), indent=2))
        return True
    if args.as_csv:
        print(to_csv(result), end="")
        return True
    return False


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "interfaces":
        result = inspect_interfaces()
        if not _emit_structured(result, args):
            if result.ok:
                print(f"Hostname: {result.hostname}")
                print(f"Interfaces: {', '.join(result.interfaces) or 'none reported'}")
                print(f"Addresses: {', '.join(result.addresses) or 'none reported'}")
            else:
                print(f"Interface inspection failed: {result.error}")
        return 0 if result.ok else 1

    if args.command == "dns":
        result = resolve_hostname(args.hostname)
        if not _emit_structured(result, args):
            if result.ok:
                print(f"{result.hostname}: {', '.join(result.addresses)}")
            else:
                print(f"{result.hostname}: resolution failed: {result.error}")
        return 0 if result.ok else 1

    if args.command == "tcp":
        result = check_tcp(args.host, args.port, args.timeout)
        if not _emit_structured(result, args):
            if result.ok:
                print(f"{result.host}:{result.port}: reachable ({result.latency_ms:.2f} ms)")
            else:
                print(f"{result.host}:{result.port}: connection failed: {result.error}")
        return 0 if result.ok else 1

    if args.command == "tcp-summary":
        result = summarize_tcp(args.host, args.port, args.count, args.timeout)
        if not _emit_structured(result, args):
            if result.ok:
                print(f"{result.host}:{result.port}: {result.successes}/{result.attempts} successful")
                print(
                    f"Latency ms: min {result.min_latency_ms:.2f}, "
                    f"avg {result.avg_latency_ms:.2f}, max {result.max_latency_ms:.2f}"
                )
                if result.failures:
                    print(f"Failures: {result.failures}")
            else:
                detail = result.errors[0] if result.errors else "no successful connections"
                print(f"{result.host}:{result.port}: summary failed: {detail}")
        return 0 if result.ok else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
