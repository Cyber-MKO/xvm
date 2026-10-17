"""MSI conditional statements, from "Conditional Statement Syntax" on Microsoft Learn.

Supported: properties, integers, quoted strings, parentheses, NOT, AND, OR,
and the comparisons = <> < > <= >=, with ~ for comparing strings without
regard to case. Two integers compare as numbers, anything else as
strings. A property alone is true when it has a value. An unset property
is the empty string. Other forms raise ConditionError.
"""

from __future__ import annotations

import re

_TOKEN = re.compile(
    r'\s*(?:(?P<str>"[^"]*")|(?P<int>-?\d+)|(?P<op>~?(?:<>|<=|>=|=|<|>))'
    r"|(?P<paren>[()])|(?P<word>[A-Za-z_#$%!?&][\w.]*))"
)
_COMPARISONS = {
    "=": lambda a, b: a == b,
    "<>": lambda a, b: a != b,
    "<": lambda a, b: a < b,
    ">": lambda a, b: a > b,
    "<=": lambda a, b: a <= b,
    ">=": lambda a, b: a >= b,
}


class ConditionError(ValueError):
    pass


def _tokens(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos = 0
    text = text.rstrip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise ConditionError(f"cannot read condition at {text[pos:]!r}")
        kind = m.lastgroup or ""
        out.append((kind, m.group(kind)))
        pos = m.end()
    return out


class _Parser:
    def __init__(self, text: str, properties: dict[str, str]):
        self.tokens = _tokens(text)
        self.pos = 0
        self.properties = properties
        self.used: set[str] = set()

    def peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> tuple[str, str]:
        token = self.peek()
        if token is None:
            raise ConditionError("condition ends early")
        self.pos += 1
        return token

    def keyword(self, word: str) -> bool:
        token = self.peek()
        if token and token[0] == "word" and token[1].upper() == word:
            self.pos += 1
            return True
        return False

    def expr(self) -> bool:
        value = self.term()
        while self.keyword("OR"):
            value = self.term() or value
        return value

    def term(self) -> bool:
        value = self.factor()
        while self.keyword("AND"):
            value = self.factor() and value
        return value

    def factor(self) -> bool:
        if self.keyword("NOT"):
            return not self.factor()
        token = self.peek()
        if token == ("paren", "("):
            self.take()
            value = self.expr()
            if self.take() != ("paren", ")"):
                raise ConditionError("missing )")
            return value
        left = self.operand()
        token = self.peek()
        if token and token[0] == "op":
            self.take()
            op = token[1]
            right = self.operand()
            return self.compare(left, op, right)
        return left not in ("", None)

    def operand(self) -> str | int:
        kind, text = self.take()
        if kind == "str":
            return text[1:-1]
        if kind == "int":
            return int(text)
        if kind == "word" and text.upper() not in ("AND", "OR", "NOT"):
            self.used.add(text)
            value = self.properties.get(text, "")
            return int(value) if re.fullmatch(r"-?\d+", value) else value
        raise ConditionError(f"unexpected {text!r}")

    def compare(self, left: str | int, op: str, right: str | int) -> bool:
        fold = op.startswith("~")
        op = op.lstrip("~")
        if isinstance(left, int) and isinstance(right, int):
            return _COMPARISONS[op](left, right)
        a, b = str(left), str(right)
        if fold:
            a, b = a.lower(), b.lower()
        return _COMPARISONS[op](a, b)


def evaluate(text: str, properties: dict[str, str]) -> tuple[bool, set[str]]:
    """The condition's value and the property names it reads."""
    if not text.strip():
        return True, set()
    parser = _Parser(text, properties)
    value = parser.expr()
    if parser.peek() is not None:
        raise ConditionError(f"unexpected {parser.peek()[1]!r}")
    return value, parser.used
