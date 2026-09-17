from netscope.network import classify_network


def test_classifies_private_ipv4_prefix_without_enumeration():
    result = classify_network("10.20.30.0/24")
    assert result.ok is True
    assert result.network == "10.20.30.0/24"
    assert result.version == 4
    assert result.prefix_length == 24
    assert result.network_address == "10.20.30.0"
    assert result.last_address == "10.20.30.255"
    assert result.num_addresses == 256
    assert result.scope == "private"


def test_classifies_ipv6_documentation_prefix():
    result = classify_network("2001:db8::/32")
    assert result.ok is True
    assert result.version == 6
    assert result.prefix_length == 32
    assert result.network_address == "2001:db8::"
    assert result.last_address == "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
    assert result.num_addresses == 2**96


def test_rejects_host_bits_in_prefix_instead_of_silently_normalizing():
    result = classify_network("10.20.30.40/24")
    assert result.ok is False
    assert result.error == "network must be a canonical IPv4 or IPv6 prefix"


def test_rejects_hostname_and_control_characters():
    assert classify_network("example.com/24").ok is False
    assert classify_network("10.0.0.0/24\nignored").ok is False


def test_result_is_json_friendly():
    payload = classify_network("192.0.2.0/24").to_dict()
    assert payload["network"] == "192.0.2.0/24"
    assert payload["num_addresses"] == 256
    assert payload["ok"] is True
