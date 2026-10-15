"""Offline Info-column predicates independent of the installed TShark filter grammar.

Wireshark 4.2+ exposes _ws.col.info, while older supported TShark releases may
only export the Info column. These predicates therefore run after dissection.
All groups are OR; all clauses inside one group are AND (disjunctive normal form).
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import TypeAlias

from .filters import FilterError

OPERATORS = frozenset({
    "contains", "not_contains", "equals", "not_equals", "starts_with", "ends_with",
})
MAX_QUERY_BYTES = 4096
MAX_GROUPS = 8
MAX_CLAUSES = 8
MAX_TOTAL_CLAUSES = 32
MAX_TEXT = 200


@dataclass(frozen=True)
class InfoRule:
    operator: str
    value: str
    case_sensitive: bool = False


InfoGroups: TypeAlias = tuple[tuple[InfoRule, ...], ...]


def parse_info_filters(raw: str) -> InfoGroups:
    """Reject invalid/oversized untrusted filter JSON before executing TShark."""
    if not raw:
        return ()
    if len(raw.encode("utf-8")) > MAX_QUERY_BYTES:
        raise FilterError("Info条件が長すぎます。条件を減らしてください")
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise FilterError("Info条件のJSON形式が不正です") from exc
    if not isinstance(document, dict) or set(document) != {"groups"}:
        raise FilterError("Info条件の形式が不正です")
    data = document["groups"]
    if not isinstance(data, list) or len(data) > MAX_GROUPS:
        raise FilterError("Info条件はORグループ8個以内にしてください")
    result: list[tuple[InfoRule, ...]] = []
    total = 0
    for group in data:
        if not isinstance(group, list) or not (1 <= len(group) <= MAX_CLAUSES):
            raise FilterError("Info条件はグループごとに1〜8件にしてください")
        rules = []
        for source in group:
            if not isinstance(source, dict):
                raise FilterError("Info条件を確認してください")
            if set(source) - {"operator", "value", "case_sensitive"}:
                raise FilterError("不明なInfo条件の項目があります")
            op = source.get("operator")
            value = source.get("value")
            sensitive = source.get("case_sensitive", False)
            if op not in OPERATORS or not isinstance(value, str) or not (1 <= len(value) <= MAX_TEXT):
                raise FilterError("Info条件の演算子または文字列が不正です")
            if not value.strip() or not isinstance(sensitive, bool):
                raise FilterError("Info条件の大文字小文字設定または文字列が不正です")
            rules.append(InfoRule(op, value, sensitive))
        total += len(rules)
        result.append(tuple(rules))
    if total > MAX_TOTAL_CLAUSES:
        raise FilterError("Info条件は合計32件以内にしてください")
    return tuple(result)


def match_info(text: str, groups: InfoGroups) -> bool:
    if not groups:
        return True

    def matches(rule: InfoRule) -> bool:
        haystack = text if rule.case_sensitive else text.casefold()
        needle = rule.value if rule.case_sensitive else rule.value.casefold()
        if rule.operator == "contains":
            return needle in haystack
        if rule.operator == "not_contains":
            return needle not in haystack
        if rule.operator == "equals":
            return haystack == needle
        if rule.operator == "not_equals":
            return haystack != needle
        if rule.operator == "starts_with":
            return haystack.startswith(needle)
        return haystack.endswith(needle)

    return any(all(matches(rule) for rule in group) for group in groups)
