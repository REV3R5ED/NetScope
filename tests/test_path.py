import subprocess

from netscope.diagnostics import trace_path


class Completed:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_trace_path_builds_bounded_posix_command(monkeypatch):
    monkeypatch.setattr("netscope.diagnostics.platform.system", lambda: "Linux")
    monkeypatch.setattr("netscope.diagnostics.shutil.which", lambda name: f"/usr/bin/{name}")
    captured = {}

    def run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Completed("traceroute to example.test\n 1  192.0.2.1  1.0 ms\n 2  192.0.2.2  2.0 ms\n")

    monkeypatch.setattr("netscope.diagnostics.subprocess.run", run)
    result = trace_path("example.test", max_hops=5, timeout=1.5)

    assert result.ok is True
    assert result.reached is True
    assert result.hops == ("1  192.0.2.1  1.0 ms", "2  192.0.2.2  2.0 ms")
    assert captured["command"] == ["traceroute", "-n", "-m", "5", "-w", "1.5", "example.test"]
    assert captured["kwargs"]["check"] is False
    assert captured["kwargs"]["capture_output"] is True


def test_trace_path_uses_windows_tracert(monkeypatch):
    monkeypatch.setattr("netscope.diagnostics.platform.system", lambda: "Windows")
    monkeypatch.setattr("netscope.diagnostics.shutil.which", lambda name: f"C:/{name}.exe")
    captured = {}
    monkeypatch.setattr("netscope.diagnostics.subprocess.run", lambda command, **kwargs: captured.setdefault("result", Completed("  1    1 ms  192.0.2.1\n")) or captured.update(command=command))

    def run(command, **kwargs):
        captured["command"] = command
        return Completed("  1    1 ms  192.0.2.1\n")

    monkeypatch.setattr("netscope.diagnostics.subprocess.run", run)
    result = trace_path("example.test", max_hops=8, timeout=2)
    assert result.ok is True
    assert captured["command"] == ["tracert", "-d", "-h", "8", "-w", "2000", "example.test"]


def test_trace_path_rejects_unsafe_or_unbounded_input_without_running(monkeypatch):
    monkeypatch.setattr("netscope.diagnostics.subprocess.run", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not run")))
    assert trace_path("-bad", 5).error == "host must not begin with '-'"
    assert trace_path("example.test", 31).error == "max hops must be between 1 and 30"
    assert trace_path("example.test", 5, 11).error == "timeout must be greater than 0 and at most 10 seconds"


def test_trace_path_reports_missing_platform_utility(monkeypatch):
    monkeypatch.setattr("netscope.diagnostics.platform.system", lambda: "Linux")
    monkeypatch.setattr("netscope.diagnostics.shutil.which", lambda name: None)
    result = trace_path("example.test")
    assert result.ok is False
    assert result.hops == ()
    assert result.error == "traceroute is not available on this system"


def test_trace_path_preserves_partial_hops_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr("netscope.diagnostics.platform.system", lambda: "Linux")
    monkeypatch.setattr("netscope.diagnostics.shutil.which", lambda name: "/usr/bin/traceroute")
    monkeypatch.setattr("netscope.diagnostics.subprocess.run", lambda *args, **kwargs: Completed(" 1  192.0.2.1  1 ms\n 2  * * *\n", "", 1))
    result = trace_path("example.test", max_hops=2)
    assert result.ok is True
    assert result.reached is False
    assert len(result.hops) == 2
    assert "not reached" in result.error
