import json
import pytest

from app.filters import FilterError
from app.info_filters import parse_info_filters, match_info


def groups(*entries):
    return json.dumps({"groups": list(entries)}, ensure_ascii=False)


def rule(value, operator="contains", sensitive=False):
    return {"operator": operator, "value": value, "case_sensitive": sensitive}


def test_info_part_match_or_and_exclude():
    search = parse_info_filters(groups(
        [rule("Standard"), rule("example.com")],
        [rule("[SYN]")],
    ))
    assert match_info("Standard query A example.com", search)
    assert match_info("443 → 40000 [SYN]", search)
    assert not match_info("Standard query A other.net", search)
    exclude = parse_info_filters(groups([rule("syn", "not_contains")]))
    assert match_info("Standard query", exclude)
    assert not match_info("TCP [SYN]", exclude)


def test_info_unicode_case_and_exact():
    insensitive = parse_info_filters(groups([rule("GET /API")]))
    assert match_info("HTTP get /api foo", insensitive)
    sensitive = parse_info_filters(groups([rule("GET", "contains", True)]))
    assert not match_info("get", sensitive)
    exact = parse_info_filters(groups([rule('some "quoted" text', "equals")]))
    assert match_info('some "quoted" text', exact)
    assert not match_info('some "quoted" text extra', exact)
    assert match_info("Prefix suffix", parse_info_filters(groups([rule("Pre", "starts_with")])))
    assert match_info("Prefix suffix", parse_info_filters(groups([rule("suffix", "ends_with")])))
    assert match_info("", parse_info_filters(""))


@pytest.mark.parametrize("raw", [
    "{",
    "null",
    '{"groups":"not an array"}',
    '{"groups":[[]]}',
    groups([rule("x", "regex")]),
    groups([rule("", "equals")]),
    groups([rule(" ")]),
    groups([rule("x" * 201)]),
    groups([{"operator": "contains", "value": "x", "case_sensitive": 1}]),
    groups([{"operator": "contains", "value": "x", "future": True}]),
    groups(*([[rule("x")]] * 9)),
    groups([[rule("x")][0]] * 9),
])
def test_reject_malformed_and_unbounded(raw):
    with pytest.raises(FilterError):
        parse_info_filters(raw)
