"""Message templates and matching, in the spirit of TTCN-3 receive templates.

A template is a nested dict/list mirroring a decoded message, whose leaves are literal values or
matchers:

    ANY            the field must be present (any value)        TTCN-3 ``?``
    ANY_OR_OMIT    present or absent                             TTCN-3 ``*``
    OMIT           the field must be absent                      TTCN-3 ``omit``
    OneOf(a, b)    value in a set
    Range(lo, hi)  inclusive numeric range
    Pred(fn, txt)  arbitrary predicate with a description

Dict templates are partial: keys that the template does not mention are ignored. ``match``
returns a list of Mismatch records (empty means the value matches).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class Mismatch:
    path: str
    expected: str
    actual: str

    def __str__(self) -> str:
        return f"{self.path or '<message>'}: expected {self.expected}, got {self.actual}"


class Matcher:
    def match(self, value: Any, path: str) -> list[Mismatch]:  # pragma: no cover - interface
        raise NotImplementedError

    def describe(self) -> str:
        return repr(self)


class _Any(Matcher):
    def match(self, value, path):
        return []

    def describe(self):
        return "?"


class _AnyOrOmit(_Any):
    def describe(self):
        return "*"


class _Omit(Matcher):
    def match(self, value, path):
        return [Mismatch(path, "omit", _short(value))]

    def describe(self):
        return "omit"


ANY = _Any()
ANY_OR_OMIT = _AnyOrOmit()
OMIT = _Omit()
_MISSING = object()


class OneOf(Matcher):
    def __init__(self, *values):
        self.values = values

    def match(self, value, path):
        for v in self.values:
            if not match(v, value, path):
                return []
        return [Mismatch(path, self.describe(), _short(value))]

    def describe(self):
        return "one of (" + ", ".join(_short(v) for v in self.values) + ")"


class Range(Matcher):
    def __init__(self, lo, hi):
        self.lo, self.hi = lo, hi

    def match(self, value, path):
        if isinstance(value, (int, float)) and self.lo <= value <= self.hi:
            return []
        return [Mismatch(path, self.describe(), _short(value))]

    def describe(self):
        return f"({self.lo}..{self.hi})"


class Pred(Matcher):
    def __init__(self, fn: Callable[[Any], bool], description: str):
        self.fn, self.description = fn, description

    def match(self, value, path):
        try:
            ok = bool(self.fn(value))
        except Exception:  # noqa: BLE001 - a predicate that raises simply does not match
            ok = False
        return [] if ok else [Mismatch(path, self.description, _short(value))]

    def describe(self):
        return self.description


def _short(v: Any) -> str:
    if v is _MISSING:
        return "<absent>"
    s = repr(v)
    return s if len(s) <= 60 else s[:57] + "..."


def match(template: Any, value: Any, path: str = "") -> list[Mismatch]:
    if isinstance(template, Matcher):
        if value is _MISSING:
            if isinstance(template, (_AnyOrOmit, _Omit)):
                return []
            return [Mismatch(path, template.describe(), "<absent>")]
        return template.match(value, path)
    if value is _MISSING:
        return [Mismatch(path, _short(template), "<absent>")]
    if isinstance(template, dict):
        if not isinstance(value, dict):
            return [Mismatch(path, "a structure", _short(value))]
        out: list[Mismatch] = []
        for k, t in template.items():
            out += match(t, value.get(k, _MISSING), f"{path}.{k}" if path else k)
        return out
    if isinstance(template, list):
        if not isinstance(value, list) or len(value) != len(template):
            return [Mismatch(path, f"list of {len(template)}", _short(value))]
        out = []
        for i, (t, v) in enumerate(zip(template, value)):
            out += match(t, v, f"{path}[{i}]")
        return out
    if template == value:
        return []
    return [Mismatch(path, _short(template), _short(value))]


def message(name: str, **body) -> dict:
    """Template for a decoded message: ``message("rrcSetupRequest", establishmentCause="mo-Signalling")``."""
    return {"message": name, "body": body}
