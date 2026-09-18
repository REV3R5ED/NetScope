import csv
import io
import json

from netscope.cli import main


def test_network_cli_human_output(capsys):
    assert main(["network", "192.0.2.0/24"]) == 0
    output = capsys.readouterr().out
    assert "192.0.2.0/24: IPv4 /24" in output
    assert "Range: 192.0.2.0 - 192.0.2.255" in output
    assert "Addresses: 256" in output


def test_network_cli_json_output(capsys):
    assert main(["network", "2001:db8::/126", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["network"] == "2001:db8::/126"
    assert payload["version"] == 6
    assert payload["num_addresses"] == 4
    assert payload["ok"] is True


def test_network_cli_csv_output(capsys):
    assert main(["network", "10.0.0.0/30", "--csv"]) == 0
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert len(rows) == 1
    assert rows[0]["network"] == "10.0.0.0/30"
    assert rows[0]["num_addresses"] == "4"
    assert rows[0]["ok"] == "True"


def test_network_cli_rejects_host_bits(capsys):
    assert main(["network", "10.0.0.1/24"]) == 1
    output = capsys.readouterr().out
    assert "classification failed" in output
    assert "canonical IPv4 or IPv6 prefix" in output
