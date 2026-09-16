import socket

from netscope.diagnostics import check_tcp, resolve_hostname, summarize_tcp, trace_path


def test_dns_rejects_non_string_hostname_without_resolver(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("resolver should not be touched")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    for hostname in (None, 123, True, object()):
        result = resolve_hostname(hostname)
        assert result.ok is False
        assert result.hostname == ""
        assert result.error == "hostname must be a string"


def test_tcp_rejects_non_string_host_without_network(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("network should not be touched")

    monkeypatch.setattr(socket, "create_connection", unexpected)
    for host in (None, 123, True, object()):
        result = check_tcp(host, 443)
        assert result.ok is False
        assert result.host == ""
        assert result.error == "host must be a string"


def test_summary_rejects_non_string_host_without_attempts(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("connection attempts should not run")

    monkeypatch.setattr("netscope.diagnostics.check_tcp", unexpected)
    for host in (None, 123, True, object()):
        result = summarize_tcp(host, 443)
        assert result.ok is False
        assert result.attempts == 0
        assert result.host == ""
        assert result.errors == ("host must be a string",)


def test_path_rejects_non_string_host_before_subprocess(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("subprocess should not run")

    monkeypatch.setattr("netscope.diagnostics.subprocess.run", unexpected)
    for host in (None, 123, True, object()):
        result = trace_path(host)
        assert result.ok is False
        assert result.host == ""
        assert result.hops == ()
        assert result.error == "host must be a string"


def test_host_controls_are_rejected_before_external_activity(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("external activity should not run")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    monkeypatch.setattr(socket, "create_connection", unexpected)
    monkeypatch.setattr("netscope.diagnostics.check_tcp", unexpected)
    monkeypatch.setattr("netscope.diagnostics.subprocess.run", unexpected)

    for host in ("example.test\nforged", "example.test\x00suffix", "example.test\x7f"):
        dns = resolve_hostname(host)
        tcp = check_tcp(host, 443)
        summary = summarize_tcp(host, 443)
        path = trace_path(host)

        assert dns.ok is False
        assert dns.error == "hostname must not contain control characters"
        assert tcp.ok is False
        assert tcp.error == "host must not contain control characters"
        assert summary.ok is False
        assert summary.attempts == 0
        assert summary.errors == ("host must not contain control characters",)
        assert path.ok is False
        assert path.hops == ()
        assert path.error == "host must not contain control characters"


def test_tcp_rejects_non_integer_ports_without_network(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("network should not be touched")

    monkeypatch.setattr(socket, "create_connection", unexpected)
    for port in (443.0, True, "443", None):
        result = check_tcp("example.test", port)
        assert result.ok is False
        assert result.error == "port must be between 1 and 65535"


def test_tcp_rejects_non_numeric_timeouts_without_network(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("network should not be touched")

    monkeypatch.setattr(socket, "create_connection", unexpected)
    for timeout in (True, "3", None):
        result = check_tcp("example.test", 443, timeout=timeout)
        assert result.ok is False
        assert result.error == "timeout must be finite, greater than 0, and at most 30 seconds"


def test_summary_rejects_non_integer_count_without_attempts(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("connection attempts should not run")

    monkeypatch.setattr("netscope.diagnostics.check_tcp", unexpected)
    for count in (3.0, True, "3", None):
        result = summarize_tcp("example.test", 443, count=count)
        assert result.ok is False
        assert result.attempts == 0
        assert result.errors == ("count must be between 1 and 10",)


def test_path_rejects_non_integer_hop_limit_before_subprocess(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("subprocess should not run")

    monkeypatch.setattr("netscope.diagnostics.subprocess.run", unexpected)
    for max_hops in (15.0, True, "15", None):
        result = trace_path("example.test", max_hops=max_hops)
        assert result.ok is False
        assert result.hops == ()
        assert result.error == "max hops must be between 1 and 30"
