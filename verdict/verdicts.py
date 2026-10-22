"""Verdicts and the exception that carries a failing check out of a test case."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from verdict.templates import Mismatch


class Verdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONC = "INCONC"  # the preamble could not bring the UE into the initial condition
    ERROR = "ERROR"    # the test system itself failed


class VerdictError(AssertionError):
    """Raised by a failing check. Carries everything the report needs to explain the failure."""

    def __init__(self, verdict: Verdict, reason: str, *, step: str | None = None, pdu: Any = None,
                 mismatches: list["Mismatch"] | None = None, expected: str | None = None, capture: Any = None):
        super().__init__(reason)
        self.verdict = verdict
        self.reason = reason
        self.step = step
        self.pdu = pdu
        self.mismatches = mismatches or []
        self.expected = expected
        self.capture = capture
