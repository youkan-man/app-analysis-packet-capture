import json
import pytest

from app.filters import (
    FilterError,
    compile_native_rule,
    compile_native_rules,
    match_column_rule,
    parse_filter_groups,
    split_group,
)


def payload(*groups):
    return json.dumps({"groups": list(groups)}, ensure_ascii=False)


def column(field, value, operator="equals", case=False):
    return {"scope": "column", "field": field, "operator": operator, "value": value, "case_sensitive": case}


def native(field, value="", operator="equals", kind="string"):
    return {"scope": "wireshark", "field": field, "operator": operator, "value": value, "kind": kind, "case_sensitive": False}


def test_every_visible_column_uses_same_generic_rule_model():
    groups = parse_filter_groups(payload([
        column("source", "192.0.2.10"),
        column("info", "QUERY", "contains"),
        column("length", "42", "greater_equal"),
    ]))
    rules, native_rules = split_group(groups[0])
    assert not native_rules
    row = {"source": "192.0.2.10", "info": "Standard query A example.com", "length": 60}
    assert all(match_column_rule(row, rule) for rule in rules)
    assert not match_column_rule(row, parse_filter_groups(payload([column("destination", "8.8.4.4")]))[0][0])


def test_case_numeric_and_text_operators():
    assert match_column_rule({"protocol": "TCP"}, parse_filter_groups(payload([column("protocol", "tcp", "equals")]))[0][0])
    assert not match_column_rule({"protocol": "TCP"}, parse_filter_groups(payload([column("protocol", "tcp", "equals", True)]))[0][0])
    assert match_column_rule({"info": "prefix-middle-suffix"}, parse_filter_groups(payload([column("info", "prefix", "starts_with")]))[0][0])
    assert match_column_rule({"info": "prefix-middle-suffix"}, parse_filter_groups(payload([column("info", "suffix", "ends_with")]))[0][0])
    assert match_column_rule({"number": 8}, parse_filter_groups(payload([column("number", "7", "greater")]))[0][0])


def test_protocol_detail_rules_compile_safely():
    rules = parse_filter_groups(payload([
        native("ip.src", "203.0.113.3", kind="address"),
        native("tcp.port", "443", kind="number"),
        native("http.host", "example.com", operator="contains"),
    ]))[0]
    assert compile_native_rules(rules) == '(ip.src == 203.0.113.3) && (tcp.port == 443) && (http.host contains "example.com")'
    assert compile_native_rule(parse_filter_groups(payload([native("tcp.flags.syn", operator="exists")]))[0][0]) == "tcp.flags.syn"
    assert compile_native_rule(parse_filter_groups(payload([native("http.host", "bad", operator="not_contains")]))[0][0]) == '!(http.host contains "bad")'


@pytest.mark.parametrize("raw", [
    "{", "null", '{"groups":"bad"}', '{"groups":[[]]}',
    payload([column("unknown", "x")]),
    payload([column("number", "not-a-number", "greater")]),
    payload([native("ip.src && tcp", "1.2.3.4", kind="address")]),
    payload([native("ip.src", "1.2.3.4;tcp", kind="address")]),
    payload([native("tcp.port", "443 || udp", kind="number")]),
    payload(*([[column("info", "x")]] * 9)),
])
def test_rejects_unbounded_or_injected_rules(raw):
    with pytest.raises(FilterError):
        parse_filter_groups(raw)
