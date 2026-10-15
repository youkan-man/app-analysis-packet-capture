import pytest
from app.filters import FilterError, compile_filter


def rule(field, value="", kind="string", operator="==", negate=False):
    return {"type": "rule", "field": field, "value": value,
            "kind": kind, "operator": operator, "negate": negate}


def test_nested_boolean_and_typed_literals():
    expression = compile_filter({
        "type": "group", "join": "and", "children": [
            rule("ip.addr", "192.0.2.10", kind="address"),
            {"type": "group", "join": "or", "negate": True, "children": [
                rule("tcp.port", "443", kind="number"),
                rule("dns.qry.name", "example.com", operator="contains"),
            ]},
        ],
    })
    assert expression == '(ip.addr == 192.0.2.10 && !((tcp.port == 443 || dns.qry.name contains "example.com")))'


def test_string_escapes_injection():
    expression = compile_filter(rule("http.host", 'hello" || tcp || "'))
    assert '\\"' in expression
    assert expression.count("http.host") == 1


@pytest.mark.parametrize("node", [
    rule("ip.src && tcp", "1.2.3.4", kind="address"),
    rule("tcp.port", "1 || udp", kind="number"),
    rule("ip.src", "1.2.3.4; rm", kind="address"),
    rule("http.host", "", kind="string"),
    rule("tcp.port", "443", kind="number", operator="contains"),
    {"type": "group", "join": "xor", "children": []},
    {"type": "group", "join": "and", "children": "invalid"},
])
def test_invalid_filter_nodes_rejected(node):
    with pytest.raises(FilterError):
        compile_filter(node)


def test_exists_and_empty_group():
    assert compile_filter(rule("tcp", operator="exists")) == "tcp"
    assert compile_filter({"type": "group", "children": []}) == ""
