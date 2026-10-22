"""Templates, reports and the verdict semantics of the System Simulator."""

import pytest

from verdict.report import format_failure, hexdump
from verdict.ss import SystemSimulator
from verdict.templates import ANY, ANY_OR_OMIT, OMIT, OneOf, Pred, Range, match, message
from verdict.verdicts import Verdict, VerdictError


def test_template_literals_and_partial_dicts():
    value = {"message": "x", "body": {"a": 1, "b": {"c": 2}, "extra": 9}}
    assert match(message("x", a=1, b={"c": 2}), value) == []
    mism = match(message("x", a=2), value)
    assert [str(m) for m in mism] == ["body.a: expected 2, got 1"]


def test_template_matchers():
    assert match({"k": ANY}, {"k": None}) == []
    assert match({"k": ANY}, {}) != []
    assert match({"k": ANY_OR_OMIT}, {}) == []
    assert match({"k": OMIT}, {}) == []
    assert match({"k": OMIT}, {"k": 1}) != []
    assert match({"k": OneOf(1, 2)}, {"k": 2}) == []
    assert match({"k": OneOf(1, 2)}, {"k": 3}) != []
    assert match({"k": Range(0, 9)}, {"k": 9}) == []
    assert match({"k": Range(0, 9)}, {"k": 10}) != []
    assert match({"k": Pred(lambda v: v % 2 == 0, "even")}, {"k": 3})[0].expected == "even"


def test_template_lists_are_exact_length():
    assert match([1, 2], [1, 2]) == []
    assert match([1, 2], [1, 2, 3])[0].expected == "list of 2"


def test_hexdump_brackets_highlighted_bytes():
    lines = hexdump(bytes(range(4)), [(1, 3)])
    assert lines == ["    0000  00 [01][02] 03 "]


def test_expect_failure_is_fail_with_step_and_highlight():
    ss = SystemSimulator(log_level="off")
    ss.ue.power_on()
    ss.ue.register()
    with pytest.raises(VerdictError) as e:
        with ss.step(1, "Check cause"):
            ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest", establishmentCause="emergency"))
    err = e.value
    assert err.verdict is Verdict.FAIL
    assert err.step == "1: Check cause"
    report = format_failure(err, "T", "t")
    assert "» body.establishmentCause = 'mo-Signalling'" in report
    assert "[06]" in report  # the byte that carries the cause is bracketed


def test_failure_in_preamble_is_inconclusive():
    ss = SystemSimulator(log_level="off")
    with pytest.raises(VerdictError) as e:
        with ss.preamble():
            ss.expect(channel="UL-CCCH", within_ms=50)  # the UE was never asked to register
    assert e.value.verdict is Verdict.INCONC
    assert "no uplink message within 50 ms" in e.value.reason


def test_expect_silence_reports_unexpected_message():
    ss = SystemSimulator(log_level="off")
    ss.ue.power_on()
    ss.ue.register()
    with pytest.raises(VerdictError, match="unexpected uplink message"):
        ss.expect_silence(100)


def test_full_registration_preamble_is_reproducible():
    a, b = SystemSimulator(seed=3, log_level="off"), SystemSimulator(seed=3, log_level="off")
    assert a.register() == b.register()
    assert [e["summary"] for e in a.events] == [e["summary"] for e in b.events]
