"""Typed screen-data filters and safe Wireshark-field compilation.

The browser never needs to construct Wireshark syntax for the common path.
Rules over visible packet columns are evaluated on decoded row data. Rules from
protocol-detail fields are validated and compiled into native TShark display
filters behind the API boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Iterable, Mapping, TypeAlias

FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*(?:#[0-9]+)?$")
NUMBER = re.compile(r"^-?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?)$")
ADDRESS = re.compile(r"^[0-9A-Fa-f:.]+(?:/\d{1,3})?$")
MAX_QUERY_BYTES = 16 * 1024
MAX_GROUPS = 8
MAX_RULES_PER_GROUP = 8
MAX_RULES = 32
MAX_VALUE = 512

COLUMN_TYPES: dict[str, str] = {
    "number": "number",
    "time": "number",
    "source": "string",
    "destination": "string",
    "protocol": "string",
    "length": "number",
    "info": "string",
}
STRING_OPERATORS = frozenset({
    "equals", "not_equals", "contains", "not_contains",
    "starts_with", "ends_with",
})
NUMBER_OPERATORS = frozenset({
    "equals", "not_equals", "greater", "greater_equal", "less", "less_equal",
})
NATIVE_OPERATORS = frozenset({
    "equals", "not_equals", "greater", "greater_equal", "less", "less_equal",
    "contains", "not_contains", "exists", "not_exists",
})
KINDS = frozenset({"string", "number", "address"})


class FilterError(ValueError):
    pass


@dataclass(frozen=True)
class FilterRule:
    scope: str
    field: str
    operator: str
    value: str = ""
    kind: str = "string"
    case_sensitive: bool = False


FilterGroups: TypeAlias = tuple[tuple[FilterRule, ...], ...]


def parse_filter_groups(raw: str) -> FilterGroups:
    """Parse bounded DNF groups: groups are OR, rules within one group are AND."""
    if not raw:
        return ()
    if len(raw.encode("utf-8")) > MAX_QUERY_BYTES:
        raise FilterError("フィルター条件が長すぎます。条件を減らしてください")
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise FilterError("フィルター条件のJSON形式が不正です") from exc
    if not isinstance(document, dict) or set(document) != {"groups"}:
        raise FilterError("フィルター条件の形式が不正です")
    source_groups = document["groups"]
    if not isinstance(source_groups, list) or len(source_groups) > MAX_GROUPS:
        raise FilterError("フィルターはORグループ8個以内にしてください")

    groups: list[tuple[FilterRule, ...]] = []
    total = 0
    for source_group in source_groups:
        if not isinstance(source_group, list) or not (1 <= len(source_group) <= MAX_RULES_PER_GROUP):
            raise FilterError("各グループの条件は1〜8件にしてください")
        rules: list[FilterRule] = []
        for source in source_group:
            rules.append(_parse_rule(source))
        total += len(rules)
        groups.append(tuple(rules))
    if total > MAX_RULES:
        raise FilterError("フィルター条件は合計32件以内にしてください")
    return tuple(groups)


def _parse_rule(source: Any) -> FilterRule:
    if not isinstance(source, dict):
        raise FilterError("フィルター条件を確認してください")
    allowed = {"scope", "field", "operator", "value", "kind", "case_sensitive"}
    if set(source) - allowed:
        raise FilterError("不明なフィルター項目があります")
    scope = source.get("scope")
    field = source.get("field")
    operator = source.get("operator")
    value = source.get("value", "")
    kind = source.get("kind", "string")
    case_sensitive = source.get("case_sensitive", False)
    if scope not in {"column", "wireshark"}:
        raise FilterError("フィルター対象が不正です")
    if not isinstance(field, str) or not field:
        raise FilterError("フィールドを指定してください")
    if not isinstance(operator, str):
        raise FilterError("比較方法を指定してください")
    if not isinstance(value, str) or len(value) > MAX_VALUE:
        raise FilterError("比較値は512文字以内にしてください")
    if not isinstance(case_sensitive, bool):
        raise FilterError("大文字小文字の指定が不正です")

    if scope == "column":
        field_type = COLUMN_TYPES.get(field)
        if field_type is None:
            raise FilterError("画面にない列は列フィルターに指定できません")
        accepted = NUMBER_OPERATORS if field_type == "number" else STRING_OPERATORS
        if operator not in accepted or not value:
            raise FilterError("列と比較方法、比較値の組み合わせが不正です")
        if field_type == "number" and not NUMBER.fullmatch(value.strip()):
            raise FilterError("数値列の比較値が不正です")
        kind = field_type
    else:
        if not FIELD.fullmatch(field):
            raise FilterError("Wiresharkフィールド名が不正です")
        if operator not in NATIVE_OPERATORS:
            raise FilterError("この比較方法はプロトコル詳細に使用できません")
        if kind not in KINDS:
            raise FilterError("比較値の種類が不正です")
        if operator not in {"exists", "not_exists"} and not value:
            raise FilterError("比較値を入力してください")
        if kind == "number" and value and not NUMBER.fullmatch(value.strip()):
            raise FilterError("数値の形式が不正です")
        if kind == "address" and value and not ADDRESS.fullmatch(value.strip()):
            raise FilterError("IP/MAC/CIDRの形式が不正です")
        if operator in {"contains", "not_contains"} and kind != "string":
            raise FilterError("含む/含まないは文字列フィールドで使用してください")

    return FilterRule(scope, field, operator, value, kind, case_sensitive)


def split_group(group: Iterable[FilterRule]) -> tuple[tuple[FilterRule, ...], tuple[FilterRule, ...]]:
    columns: list[FilterRule] = []
    native: list[FilterRule] = []
    for rule in group:
        (columns if rule.scope == "column" else native).append(rule)
    return tuple(columns), tuple(native)


def match_column_rules(row: Mapping[str, Any], rules: Iterable[FilterRule]) -> bool:
    return all(match_column_rule(row, rule) for rule in rules)


def match_column_rule(row: Mapping[str, Any], rule: FilterRule) -> bool:
    actual = row.get(rule.field, "")
    if rule.kind == "number":
        try:
            left = float(actual)
            right = _number(rule.value)
        except (TypeError, ValueError):
            return False
        return {
            "equals": left == right,
            "not_equals": left != right,
            "greater": left > right,
            "greater_equal": left >= right,
            "less": left < right,
            "less_equal": left <= right,
        }[rule.operator]

    left = str(actual)
    right = rule.value
    if not rule.case_sensitive:
        left = left.casefold()
        right = right.casefold()
    return {
        "equals": left == right,
        "not_equals": left != right,
        "contains": right in left,
        "not_contains": right not in left,
        "starts_with": left.startswith(right),
        "ends_with": left.endswith(right),
    }[rule.operator]


def compile_native_rules(rules: Iterable[FilterRule]) -> str:
    expressions = [compile_native_rule(rule) for rule in rules]
    return " && ".join(f"({expression})" for expression in expressions)


def compile_native_rule(rule: FilterRule) -> str:
    if rule.scope != "wireshark" or not FIELD.fullmatch(rule.field):
        raise FilterError("プロトコル詳細フィルターが不正です")
    if rule.operator == "exists":
        return rule.field
    if rule.operator == "not_exists":
        return f"!({rule.field})"
    rhs = _native_literal(rule)
    mapping = {
        "equals": "==", "not_equals": "!=", "greater": ">", "greater_equal": ">=",
        "less": "<", "less_equal": "<=", "contains": "contains",
    }
    if rule.operator == "not_contains":
        return f"!({rule.field} contains {rhs})"
    return f"{rule.field} {mapping[rule.operator]} {rhs}"


def _native_literal(rule: FilterRule) -> str:
    value = rule.value.strip()
    if rule.kind == "number":
        if not NUMBER.fullmatch(value):
            raise FilterError("数値の形式が不正です")
        return value
    if rule.kind == "address":
        if not ADDRESS.fullmatch(value):
            raise FilterError("アドレスの形式が不正です")
        return value
    return json.dumps(rule.value, ensure_ascii=False)


def _number(value: str) -> float:
    value = value.strip()
    if value.lower().startswith("0x"):
        return float(int(value, 16))
    return float(value)
