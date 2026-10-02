"""Command-line interface for NetScope."""

from __future__ import annotations

import argparse
import dataclasses
import json
import math

from . import __version__
from .address import classify_address
from .diagnostics import (
    DNSResult,
    PingResult,
    TCPResult,
    TCPSummaryResult,
    check_tcp,
    evaluate_tcp_summary_gates,
    inspect_interfaces,
    latency_drift_percent,
    load_latency_baseline,
    ping_host,
    resolve_hostname,
    summarize_tcp,
    trace_path,
)
from .dns import DNSFamilyResult, resolve_hostname_family
from .network import classify_network
from .profiles import (
    ProfileError,
    discover_profiles_file,
    execute_check,
    load_profile,
)
from .reporting import DictResult, to_csv
from .schemas import load_schema, schema_names
from .tls import TLSResult, check_tls, evaluate_tls_gates


def _add_output_options(parser: argparse.ArgumentParser) -> None:
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        "--json", action="store_true", dest="as_json", help="Emit machine-readable JSON"
    )
    output.add_argument(
        "--csv", action="store_true", dest="as_csv", help="Emit a one-record CSV report"
    )


def _success_rate(value: str) -> float:
    rate = float(value)
    if not math.isfinite(rate) or not 0.0 <= rate <= 100.0:
        raise argparse.ArgumentTypeError("must be a finite value between 0 and 100")
    return rate


def _nonnegative_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or number < 0.0:
        raise argparse.ArgumentTypeError("must be a finite value of zero or greater")
    return number


def _tcp_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "must be an integer between 1 and 65535"
        ) from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("must be an integer between 1 and 65535")
    return port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Defensive network visibility and diagnostics"
    )
    parser.add_argument(
        "--version", action="version", version=f"NetScope {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    interfaces = subparsers.add_parser(
        "interfaces", help="Inspect local interfaces and host addresses"
    )
    _add_output_options(interfaces)
    address = subparsers.add_parser(
        "address", help="Classify one literal IPv4 or IPv6 address locally"
    )
    address.add_argument("address")
    _add_output_options(address)
    network = subparsers.add_parser(
        "network", help="Classify one canonical IPv4 or IPv6 network prefix locally"
    )
    network.add_argument("network")
    _add_output_options(network)
    dns = subparsers.add_parser(
        "dns", help="Resolve a hostname with the system DNS resolver"
    )
    dns.add_argument("hostname")
    dns.add_argument(
        "--family",
        choices=("ipv4", "ipv6"),
        help="Restrict resolution to one address family",
    )
    _add_output_options(dns)
    tcp = subparsers.add_parser("tcp", help="Test one explicit TCP host and port")
    tcp.add_argument("host")
    tcp.add_argument("port", type=_tcp_port)
    tcp.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Connection timeout in seconds (max 30)",
    )
    _add_output_options(tcp)
    summary = subparsers.add_parser(
        "tcp-summary", help="Summarize bounded latency checks for one endpoint"
    )
    summary.add_argument("host")
    summary.add_argument("port", type=_tcp_port)
    summary.add_argument(
        "--count", type=int, default=3, help="Connection attempts (1-10, default 3)"
    )
    summary.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Per-attempt timeout in seconds (max 30)",
    )
    gates = summary.add_mutually_exclusive_group()
    gates.add_argument(
        "--require-all",
        action="store_true",
        help="Return exit code 1 if any bounded connection attempt fails",
    )
    gates.add_argument(
        "--min-success-rate",
        type=_success_rate,
        metavar="PERCENT",
        help="Return exit code 1 when success rate is below PERCENT (0-100)",
    )
    summary.add_argument(
        "--max-jitter-ms",
        type=_nonnegative_float,
        metavar="MS",
        help="Return exit code 1 when measured latency jitter exceeds MS",
    )
    summary.add_argument(
        "--max-avg-latency-ms",
        type=_nonnegative_float,
        metavar="MS",
        help="Return exit code 1 when average successful connection latency exceeds MS",
    )
    summary.add_argument(
        "--baseline",
        metavar="FILE",
        help="JSON report from a previous tcp-summary run used for drift comparison",
    )
    summary.add_argument(
        "--max-latency-drift-pct",
        type=_nonnegative_float,
        metavar="PCT",
        help="Return exit code 1 when latency drift vs baseline exceeds PCT percent",
    )
    _add_output_options(summary)
    tls = subparsers.add_parser(
        "tls", help="Run one bounded TLS handshake against an explicit host and port"
    )
    tls.add_argument("host")
    tls.add_argument("port", type=_tcp_port)
    tls.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Handshake timeout in seconds (max 30)",
    )
    tls.add_argument(
        "--min-days-cert-valid",
        type=_nonnegative_float,
        metavar="DAYS",
        help="Return exit code 1 when the certificate expires in fewer than DAYS",
    )
    _add_output_options(tls)
    ping = subparsers.add_parser(
        "ping", help="Send bounded ICMP echo requests to one explicit host"
    )
    ping.add_argument("host")
    ping.add_argument(
        "--count", type=int, default=4, help="Echo requests (1-10, default 4)"
    )
    ping.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Per-request timeout in seconds (max 10)",
    )
    ping.add_argument(
        "--family",
        choices=("any", "ipv4", "ipv6"),
        default="any",
        help="Address family for the echo requests (default any)",
    )
    _add_output_options(ping)
    path = subparsers.add_parser(
        "path", help="Trace a bounded network path to one explicit host"
    )
    path.add_argument("host")
    path.add_argument(
        "--max-hops", type=int, default=15, help="Maximum hops (1-30, default 15)"
    )
    path.add_argument(
        "--timeout", type=float, default=2.0, help="Per-hop wait in seconds (max 10)"
    )
    path.add_argument(
        "--require-reached",
        action="store_true",
        help="Return exit code 1 unless the bounded trace reaches the destination",
    )
    _add_output_options(path)
    check = subparsers.add_parser(
        "check", help="Run a saved endpoint profile from a TOML profiles file"
    )
    check.add_argument(
        "--profile", required=True, help="Name of the profile to execute"
    )
    check.add_argument(
        "--profiles",
        metavar="FILE",
        default=None,
        help="Profiles file (default: ./netscope-profiles.toml or the XDG config file)",
    )
    _add_output_options(check)
    schema = subparsers.add_parser(
        "schema", help="Print the versioned JSON Schema for a command's JSON output"
    )
    schema.add_argument(
        "schema_name",
        metavar="COMMAND",
        choices=schema_names(),
        help=f"One of: {', '.join(schema_names())}",
    )
    return parser


def _emit_structured(result: DictResult, args: argparse.Namespace) -> bool:
    if args.as_json:
        print(json.dumps(result.to_dict(), indent=2))
        return True
    if args.as_csv:
        print(to_csv(result), end="")
        return True
    return False


def _print_tcp_human(result: TCPResult) -> None:
    print(
        f"{result.host}:{result.port}: reachable ({result.latency_ms:.2f} ms)"
        if result.ok
        else f"{result.host}:{result.port}: connection failed: {result.error}"
    )


def _print_tcp_summary_human(result: TCPSummaryResult) -> None:
    if result.ok:
        print(
            f"{result.host}:{result.port}: {result.successes}/{result.attempts} "
            f"successful ({result.success_rate_percent:.2f}%)"
        )
        print(
            f"Latency ms: min {result.min_latency_ms:.2f}, "
            f"avg {result.avg_latency_ms:.2f}, max {result.max_latency_ms:.2f}, "
            f"jitter {result.jitter_ms:.2f}"
        )
        if result.baseline_avg_latency_ms is not None and (
            result.latency_drift_percent is not None
        ):
            print(
                f"Baseline avg: {result.baseline_avg_latency_ms:.2f} ms, "
                f"drift: {result.latency_drift_percent:+.2f}%"
            )
        if result.failures:
            print(f"Failures: {result.failures}")
            unique_errors = tuple(dict.fromkeys(result.errors))
            if unique_errors:
                print(f"Failure details: {'; '.join(unique_errors)}")
    else:
        detail = result.errors[0] if result.errors else "no successful connections"
        print(f"{result.host}:{result.port}: summary failed: {detail}")


def _print_tls_human(result: TLSResult) -> None:
    if result.ok:
        handshake = (
            f", {result.latency_ms:.2f} ms handshake"
            if result.latency_ms is not None
            else ""
        )
        print(
            f"{result.host}:{result.port}: TLS {result.protocol} "
            f"({result.cipher}, {result.cipher_bits} bits{handshake})"
        )
        if result.subject:
            subject = ", ".join(
                f"{name}={','.join(values)}" for name, values in result.subject.items()
            )
            print(f"Subject: {subject}")
        if result.sans:
            print(f"SANs: {', '.join(result.sans)}")
        if result.issuer:
            issuer = ", ".join(
                f"{name}={','.join(values)}" for name, values in result.issuer.items()
            )
            print(f"Issuer: {issuer}")
        if result.cert_expires_at is not None:
            print(
                f"Certificate expires: {result.cert_expires_at} "
                f"({result.days_until_expiry:.2f} days remaining)"
            )
        else:
            print("Certificate expiry: not reported by peer")
    else:
        print(f"{result.host}:{result.port}: TLS handshake failed: {result.error}")


def _print_ping_human(result: PingResult) -> None:
    if result.ok:
        print(
            f"{result.host}: {result.successes}/{result.count} replies "
            f"({result.success_rate_percent:.2f}%)"
        )
        print(
            f"Round-trip ms: min {result.min_latency_ms:.2f}, "
            f"avg {result.avg_latency_ms:.2f}, max {result.max_latency_ms:.2f}"
        )
        if result.failures:
            print(f"Failures: {result.failures}")
    else:
        detail = result.errors[0] if result.errors else "no replies received"
        print(f"{result.host}: ping failed: {detail}")


def _print_check_human(
    profile_name: str, check_type: str, result: TCPResult | TCPSummaryResult | TLSResult
) -> None:
    print(f"[{profile_name}] {check_type}")
    if isinstance(result, TLSResult):
        _print_tls_human(result)
    elif isinstance(result, TCPSummaryResult):
        _print_tcp_summary_human(result)
    else:
        _print_tcp_human(result)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "interfaces":
        interfaces_result = inspect_interfaces()
        if not _emit_structured(interfaces_result, args):
            if interfaces_result.ok:
                print(f"Hostname: {interfaces_result.hostname}")
                interfaces = ", ".join(interfaces_result.interfaces) or "none reported"
                addresses = ", ".join(interfaces_result.addresses) or "none reported"
                print(f"Interfaces: {interfaces}")
                print(f"Addresses: {addresses}")
            else:
                print(f"Interface inspection failed: {interfaces_result.error}")
        return 0 if interfaces_result.ok else 1
    if args.command == "address":
        address_result = classify_address(args.address)
        if not _emit_structured(address_result, args):
            if address_result.ok:
                summary_line = (
                    f"{address_result.address}: "
                    f"IPv{address_result.version} {address_result.scope}"
                )
                print(summary_line)
                print(f"Reverse pointer: {address_result.reverse_pointer}")
            else:
                failure = (
                    f"{address_result.address}: "
                    f"classification failed: {address_result.error}"
                )
                print(failure)
        return 0 if address_result.ok else 1
    if args.command == "network":
        network_result = classify_network(args.network)
        if not _emit_structured(network_result, args):
            if network_result.ok:
                print(
                    f"{network_result.network}: IPv{network_result.version} "
                    f"/{network_result.prefix_length} {network_result.scope}"
                )
                address_range = (
                    f"Range: {network_result.network_address} "
                    f"- {network_result.last_address}"
                )
                print(address_range)
                print(f"Addresses: {network_result.num_addresses}")
            else:
                failure = (
                    f"{network_result.network}: "
                    f"classification failed: {network_result.error}"
                )
                print(failure)
        return 0 if network_result.ok else 1
    if args.command == "dns":
        dns_result: DNSResult | DNSFamilyResult = (
            resolve_hostname_family(args.hostname, args.family)
            if args.family
            else resolve_hostname(args.hostname)
        )
        if not _emit_structured(dns_result, args):
            print(
                f"{dns_result.hostname}: {', '.join(dns_result.addresses)}"
                if dns_result.ok
                else f"{dns_result.hostname}: resolution failed: {dns_result.error}"
            )
        return 0 if dns_result.ok else 1
    if args.command == "tcp":
        tcp_result = check_tcp(args.host, args.port, args.timeout)
        if not _emit_structured(tcp_result, args):
            _print_tcp_human(tcp_result)
        return 0 if tcp_result.ok else 1
    if args.command == "tcp-summary":
        if args.max_latency_drift_pct is not None and args.baseline is None:
            parser.error("--max-latency-drift-pct requires --baseline")
        baseline_avg: float | None = None
        if args.baseline is not None:
            try:
                baseline_avg = load_latency_baseline(args.baseline)
            except ValueError as exc:
                parser.error(str(exc))
        summary_result = summarize_tcp(args.host, args.port, args.count, args.timeout)
        drift_violations: tuple[str, ...] = ()
        if args.baseline is not None and baseline_avg is not None:
            if summary_result.avg_latency_ms is not None:
                drift = latency_drift_percent(
                    summary_result.avg_latency_ms, baseline_avg
                )
                summary_result = dataclasses.replace(
                    summary_result,
                    baseline_avg_latency_ms=baseline_avg,
                    latency_drift_percent=drift,
                )
                if (
                    args.max_latency_drift_pct is not None
                    and drift > args.max_latency_drift_pct
                ):
                    drift_violations = (
                        f"latency drift {drift:+.2f}% exceeds maximum "
                        f"+{args.max_latency_drift_pct:g}% vs baseline "
                        f"{baseline_avg:.2f} ms",
                    )
        if not _emit_structured(summary_result, args):
            _print_tcp_summary_human(summary_result)
        if not summary_result.ok:
            return 1
        violations = (
            evaluate_tcp_summary_gates(
                summary_result,
                require_all=args.require_all,
                min_success_rate=args.min_success_rate,
                max_jitter_ms=args.max_jitter_ms,
                max_avg_latency_ms=args.max_avg_latency_ms,
            )
            + drift_violations
        )
        return 1 if violations else 0
    if args.command == "tls":
        tls_result = check_tls(args.host, args.port, args.timeout)
        if not _emit_structured(tls_result, args):
            _print_tls_human(tls_result)
        if not tls_result.ok:
            return 1
        violations = evaluate_tls_gates(
            tls_result, min_days_cert_valid=args.min_days_cert_valid
        )
        return 1 if violations else 0
    if args.command == "ping":
        ping_result = ping_host(args.host, args.count, args.timeout, args.family)
        if not _emit_structured(ping_result, args):
            _print_ping_human(ping_result)
        return 0 if ping_result.ok else 1
    if args.command == "path":
        path_result = trace_path(args.host, args.max_hops, args.timeout)
        if not _emit_structured(path_result, args):
            print(f"Path to {path_result.host} (max {path_result.max_hops} hops):")
            for hop in path_result.hops:
                print(hop)
            if path_result.error:
                print(f"Note: {path_result.error}")
        if not path_result.ok:
            return 1
        if args.require_reached and not path_result.reached:
            return 1
        return 0
    if args.command == "check":
        profiles_path = discover_profiles_file(args.profiles)
        if profiles_path is None:
            parser.error(
                "no profiles file found; pass --profiles FILE or create "
                "./netscope-profiles.toml"
            )
        try:
            profile = load_profile(profiles_path, args.profile)
        except ProfileError as exc:
            parser.error(str(exc))
        check_result, check_exit = execute_check(profile)
        if not _emit_structured(check_result, args):
            _print_check_human(profile.name, profile.check_type, check_result)
        return check_exit
    if args.command == "schema":
        print(json.dumps(load_schema(args.schema_name), indent=2))
        return 0
    # Unreachable: subparsers require a command, but kept as a defensive default.
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover - exercised via installed entry point
    raise SystemExit(main())
