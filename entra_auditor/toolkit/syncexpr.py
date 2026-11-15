"""A small evaluator for Entra Connect's rule expressions (the IIF(...) language of attribute flows).

Only what is needed to decide filtering is covered: the operators and the functions that Microsoft's
built-in rules use for ``cloudFiltered``, plus the common string helpers. Everything else evaluates to
UNKNOWN rather than to a guess, and UNKNOWN is contagious except where the answer doesn't depend on it
(``True || unknown`` is True; an untaken IIF branch is never evaluated).

    value = evaluate('IIF(Left([sAMAccountName], 4) = "AAD_", True, NULL)', {"sAMAccountName": "AAD_x"})

Values: str, int, bool, list (multi-valued attribute), None (NULL / attribute not present), UNKNOWN.

Assumptions, not confirmed against a live Connect server: string comparison is case-insensitive;
DNComponent returns the value of the n-th component of a distinguished name (1 = the leftmost).
Grammar and function names were taken from the expressions in Microsoft's published sample export
(github.com/microsoft/AADConnectConfigDocumenter) and the declarative-provisioning function reference.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Mapping, Optional


class _Unknown:
    def __repr__(self) -> str:
        return "UNKNOWN"

    def __bool__(self) -> bool:
        raise TypeError("UNKNOWN has no truth value; test it with `is UNKNOWN`")


UNKNOWN = _Unknown()


class ExpressionError(ValueError):
    """The text isn't an expression this parser understands."""


_TOKEN = re.compile(r"""
    \s*(?:
      (?P<string>"(?:[^"]|"")*")
    | (?P<hex>&H[0-9A-Fa-f]+)
    | (?P<number>\d+)
    | (?P<attr>\[[^\]]+\])
    | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
    | (?P<op>\|\||&&|<>|<=|>=|[=<>&+\-(),])
    )""", re.VERBOSE)


def _tokens(text: str) -> list[tuple[str, str]]:
    found, position = [], 0
    text = text.strip()
    while position < len(text):
        match = _TOKEN.match(text, position)
        if match is None or match.end() == position:
            raise ExpressionError(f"Unexpected text at position {position}: {text[position:position + 20]!r}")
        kind = match.lastgroup or ""
        found.append((kind, match.group(kind)))
        position = match.end()
    return found


# -- parsing: precedence  ||  <  &&  <  comparison  <  & + -  <  primary ------------------------------ #

Node = tuple


class _Parser:
    def __init__(self, text: str) -> None:
        self.tokens = _tokens(text)
        self.position = 0

    def peek(self) -> tuple[str, str]:
        return self.tokens[self.position] if self.position < len(self.tokens) else ("end", "")

    def take(self, value: Optional[str] = None) -> tuple[str, str]:
        token = self.peek()
        if value is not None and token[1] != value:
            raise ExpressionError(f"Expected {value!r} but found {token[1] or 'the end'!r}")
        self.position += 1
        return token

    def parse(self) -> Node:
        node = self.either()
        if self.peek()[0] != "end":
            raise ExpressionError(f"Unexpected {self.peek()[1]!r}")
        return node

    def _binary(self, operand: Callable[[], Node], operators: tuple[str, ...]) -> Node:
        node = operand()
        while self.peek()[0] == "op" and self.peek()[1] in operators:
            operator = self.take()[1]
            node = ("binary", operator, node, operand())
        return node

    def either(self) -> Node:
        return self._binary(self.both, ("||",))

    def both(self) -> Node:
        return self._binary(self.comparison, ("&&",))

    def comparison(self) -> Node:
        return self._binary(self.joined, ("=", "<>", "<", ">", "<=", ">="))

    def joined(self) -> Node:
        return self._binary(self.primary, ("&", "+", "-"))

    def primary(self) -> Node:
        kind, value = self.take()
        if kind == "string":
            return ("value", value[1:-1].replace('""', '"'))
        if kind == "hex":
            return ("value", int(value[2:], 16))
        if kind == "number":
            return ("value", int(value))
        if kind == "attr":
            return ("attr", value[1:-1])
        if kind == "op" and value == "(":
            node = self.either()
            self.take(")")
            return node
        if kind == "op" and value == "-":
            return ("binary", "-", ("value", 0), self.primary())
        if kind == "name":
            if self.peek()[1] == "(":
                self.take("(")
                arguments = []
                if self.peek()[1] != ")":
                    arguments.append(self.either())
                    while self.peek()[1] == ",":
                        self.take(",")
                        arguments.append(self.either())
                self.take(")")
                return ("call", value.lower(), arguments)
            constant = {"true": True, "false": False, "null": None}.get(value.lower(), UNKNOWN)
            return ("value", constant)
        raise ExpressionError(f"Unexpected {value or 'end of expression'!r}")


def parse(text: str) -> Node:
    return _Parser(text).parse()


# -- evaluating ------------------------------------------------------------------------------------- #

def _present(value: Any) -> bool:
    return value not in (None, "", []) and value != []


def _text(value: Any) -> Any:
    if value is UNKNOWN:
        return UNKNOWN
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return ""
    if isinstance(value, bool):
        return "True" if value else "False"
    return str(value)


def _number(value: Any) -> Any:
    if value is UNKNOWN:
        return UNKNOWN
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    try:
        return int(str(value).strip(), 0) if not isinstance(value, int) else value
    except ValueError:
        return UNKNOWN


def _truth(value: Any) -> Any:
    """CBool: None/empty is False, numbers by non-zero, 'True'/'False' text by meaning."""
    if value is UNKNOWN:
        return UNKNOWN
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None or value == "":
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    folded = str(value).strip().casefold()
    if folded in ("true", "false"):
        return folded == "true"
    try:
        return int(folded, 0) != 0
    except ValueError:
        return UNKNOWN


def _dn_component(dn: Any, index: Any) -> Any:
    text, number = _text(dn), _number(index)
    if text is UNKNOWN or number is UNKNOWN or number is None:
        return UNKNOWN
    parts = re.split(r"(?<!\\),", text)
    if not 1 <= number <= len(parts):
        return ""
    return parts[number - 1].partition("=")[2].strip()


def _call(name: str, arguments: list[Node], obj: Mapping[str, Any]) -> Any:
    if name == "iif":
        if len(arguments) != 3:
            return UNKNOWN
        condition = _truth(_eval(arguments[0], obj))
        if condition is UNKNOWN:
            return UNKNOWN
        return _eval(arguments[1 if condition else 2], obj)
    values = [_eval(a, obj) for a in arguments]
    if name in ("ispresent", "isnull", "isnullorempty"):
        if len(values) != 1 or values[0] is UNKNOWN:
            return UNKNOWN
        return _present(values[0]) if name == "ispresent" else not _present(values[0])
    if any(v is UNKNOWN for v in values):
        return UNKNOWN
    try:
        if name == "cbool":
            return _truth(values[0])
        if name in ("cstr", "trim", "lcase", "ucase", "len"):
            text = _text(values[0])
            return {"cstr": lambda: text, "trim": text.strip, "lcase": text.lower, "ucase": text.upper,
                    "len": lambda: len(text)}[name]()
        if name == "cnum":
            return _number(values[0])
        if name in ("left", "right"):
            text, count = _text(values[0]), _number(values[1])
            if count is UNKNOWN or count is None:
                return UNKNOWN
            return text[:count] if name == "left" else (text[-count:] if count else "")
        if name == "mid":
            text, start, count = _text(values[0]), _number(values[1]), _number(values[2])
            if UNKNOWN in (start, count) or None in (start, count):
                return UNKNOWN
            return text[start - 1:start - 1 + count]
        if name == "instr":
            return _text(values[0]).casefold().find(_text(values[1]).casefold()) + 1
        if name in ("bitand", "bitor"):
            a, b = _number(values[0]), _number(values[1])
            if UNKNOWN in (a, b):
                return UNKNOWN
            a, b = a or 0, b or 0
            return a & b if name == "bitand" else a | b
        if name == "not":
            truth = _truth(values[0])
            return UNKNOWN if truth is UNKNOWN else not truth
        if name == "cref":
            return values[0]
        if name == "dncomponent":
            return _dn_component(values[0], values[1])
        if name == "contains":
            haystack = values[0] if isinstance(values[0], list) else ([] if values[0] is None else [values[0]])
            return 1 if _text(values[1]).casefold() in {_text(v).casefold() for v in haystack} else 0
        if name == "valuecount":
            value = values[0]
            return len(value) if isinstance(value, list) else int(_present(value))
    except (IndexError, KeyError, TypeError):
        return UNKNOWN
    return UNKNOWN          # Error(), Word(), Item(), anything not listed: never guessed


def _compare(operator: str, left: Any, right: Any) -> Any:
    if left is UNKNOWN or right is UNKNOWN:
        return UNKNOWN
    if isinstance(left, bool) or isinstance(right, bool):
        a, b = _truth(left), _truth(right)
        if UNKNOWN in (a, b) or operator not in ("=", "<>"):
            return UNKNOWN
        return (a == b) if operator == "=" else (a != b)
    if isinstance(left, int) or isinstance(right, int):
        a, b = _number(left), _number(right)
        if UNKNOWN in (a, b):
            return UNKNOWN
        a, b = a or 0, b or 0
    else:
        a, b = _text(left).casefold(), _text(right).casefold()
    return {"=": a == b, "<>": a != b, "<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[operator]


def _eval(node: Node, obj: Mapping[str, Any]) -> Any:
    kind = node[0]
    if kind == "value":
        return node[1]
    if kind == "attr":
        wanted = node[1].casefold()
        return next((v for k, v in obj.items() if str(k).casefold() == wanted), None)
    if kind == "call":
        return _call(node[1], node[2], obj)
    operator, left_node, right_node = node[1], node[2], node[3]
    if operator in ("||", "&&"):
        decisive = operator == "||"
        left = _truth(_eval(left_node, obj))
        if left is not UNKNOWN and left is decisive:
            return decisive                         # short-circuit: the other side doesn't matter
        right = _truth(_eval(right_node, obj))
        if right is not UNKNOWN and right is decisive:
            return decisive
        return UNKNOWN if UNKNOWN in (left, right) else (not decisive)
    left, right = _eval(left_node, obj), _eval(right_node, obj)
    if operator in ("=", "<>", "<", ">", "<=", ">="):
        return _compare(operator, left, right)
    if left is UNKNOWN or right is UNKNOWN:
        return UNKNOWN
    if operator == "&":
        return _text(left) + _text(right)
    a, b = _number(left), _number(right)
    if UNKNOWN in (a, b):
        return UNKNOWN
    return (a or 0) + (b or 0) if operator == "+" else (a or 0) - (b or 0)


def evaluate(expression: str, obj: Mapping[str, Any]) -> Any:
    """The expression's value for ``obj`` (attribute name -> value), or UNKNOWN when it can't be worked out."""
    try:
        return _eval(parse(expression), obj)
    except ExpressionError:
        return UNKNOWN


def as_filter(value: Any) -> Any:
    """What an expression's result means for cloudFiltered: True, False, None (no contribution), or UNKNOWN."""
    if value is UNKNOWN or value is None:
        return value
    if value == "":
        return None
    return _truth(value)
