"""Pure, typed conversion from visual filter groups to Wireshark display filters."""
from __future__ import annotations

import json
import re
from typing import Any

FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*(?:#[0-9]+)?$")
NUMBER = re.compile(r"^-?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?)$")
ADDRESS = re.compile(r"^[0-9A-Fa-f:.]+(?:/\d{1,3})?$")
OPERATORS = {"==", "!=", ">", ">=", "<", "<=", "contains", "matches", "exists"}
KINDS = {"string", "number", "address"}


class FilterError(ValueError):
    pass


def compile_filter(node: dict[str, Any], depth: int = 0) -> str:
    """Only known operators and typed literals enter the generated expression.

    A group's children are parenthesized so switching ALL/ANY is predictable.
    Raw user-written Wireshark expressions are handled separately by TShark.
    """
    if not isinstance(node, dict) or depth > 6:
        raise FilterError("条件グループの形式または階層が不正です")
    if node.get("type") == "group":
        join = node.get("join", "and")
        if join not in {"and", "or"}:
            raise FilterError("結合条件は AND または OR を指定してください")
        children = node.get("children", [])
        if not isinstance(children, list) or len(children) > 40:
            raise FilterError("条件はグループごとに40件以内にしてください")
        exprs = [compile_filter(child, depth + 1) for child in children]
        exprs = [expr for expr in exprs if expr]
        expr = "(" + (" && " if join == "and" else " || ").join(exprs) + ")" if exprs else ""
    elif node.get("type") == "rule":
        field = str(node.get("field", "")).strip()
        operator = node.get("operator", "==")
        if not FIELD.fullmatch(field):
            raise FilterError("フィールド名を確認してください")
        if operator not in OPERATORS:
            raise FilterError("使用できない比較演算子です")
        if operator == "exists":
            expr = field
        else:
            value = str(node.get("value", "")).strip()
            kind = node.get("kind", "string")
            if kind not in KINDS or not value or len(value) > 512:
                raise FilterError("値の種類、長さ、未入力の項目を確認してください")
            if operator in {"contains", "matches"} and kind != "string":
                raise FilterError("contains / matches は文字列値で指定してください")
            if kind == "number":
                if not NUMBER.fullmatch(value):
                    raise FilterError("数値の形式が不正です")
                rhs = value
            elif kind == "address":
                if not ADDRESS.fullmatch(value):
                    raise FilterError("IP / MAC / CIDR の形式が不正です")
                rhs = value
            else:
                rhs = json.dumps(value, ensure_ascii=False)
            expr = f"{field} {operator} {rhs}"
    else:
        raise FilterError("不明な条件種類です")
    return f"!({expr})" if expr and node.get("negate") is True else expr
