import json

from netscope.diagnostics import DNSResult, InterfaceResult, PathResult, TCPSummaryResult


def test_diagnostic_results_are_json_native_and_round_trip_stable():
    results = (
        DNSResult("example.test", ("192.0.2.1", "2001:db8::1"), True),
        InterfaceResult("workstation", ("eth0", "lo"), ("192.0.2.20",), True),
        TCPSummaryResult("example.test", 443, 2, 1, 1, 50.0, 12.5, 12.5, 12.5, 0.0, True, ("refused",)),
        PathResult("example.test", 5, ("1 192.0.2.1", "2 192.0.2.2"), True, True),
    )

    for result in results:
        payload = result.to_dict()
        assert json.loads(json.dumps(payload)) == payload

    assert results[0].to_dict()["addresses"] == ["192.0.2.1", "2001:db8::1"]
    assert results[1].to_dict()["interfaces"] == ["eth0", "lo"]
    assert results[2].to_dict()["errors"] == ["refused"]
    assert results[3].to_dict()["hops"] == ["1 192.0.2.1", "2 192.0.2.2"]
