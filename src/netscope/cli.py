"""Command-line interface for NetScope."""

from __future__ import annotations

import argparse
import json

from . import __version__
from .diagnostics import resolve_hostname


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Defensive network visibility and diagnostics")
    parser.add_argument("--version", action="version", version=f"NetScope {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    dns = subparsers.add_parser("dns", help="Resolve a hostname with the system DNS resolver")
    dns.add_argument("hostname")
    dns.add_argument("--json", action="store_true", dest="as_json", help="Emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "dns":
        result = resolve_hostname(args.hostname)
        if args.as_json:
            print(json.dumps(result.to_dict(), indent=2))
        elif result.ok:
            print(f"{result.hostname}: {', '.join(result.addresses)}")
        else:
            print(f"{result.hostname}: resolution failed: {result.error}")
        return 0 if result.ok else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
