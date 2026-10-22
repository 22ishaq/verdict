"""pytest integration: fixtures, the ``tc`` marker, verdict mapping and reports.

Each test case is tagged with ``@pytest.mark.tc(id, title, spec)``. Outcomes map to verdicts:

* passed                         -> PASS
* VerdictError raised            -> its verdict (FAIL, or INCONC from a failed preamble)
* AssertionError                 -> FAIL
* any other exception            -> ERROR (a problem in the test system itself)

At the end of the session a verdict table is printed; ``--verdict-report`` writes an HTML report,
``--verdict-json`` a JSON file and ``--verdict-pcap-dir`` one Wireshark trace per test case.
"""

from __future__ import annotations

import os
import re

import pytest

from verdict.report import CaseResult, format_failure, write_html, write_json
from verdict.ss import SystemSimulator
from verdict.testbed import Testbed, UeEmulator
from verdict.verdicts import Verdict, VerdictError

_RESULTS_KEY = "_verdict_results"


def pytest_addoption(parser):
    g = parser.getgroup("verdict")
    g.addoption("--verdict-report", default=None, help="write an HTML verdict report to this path")
    g.addoption("--verdict-json", default=None, help="write verdicts as JSON to this path")
    g.addoption("--verdict-pcap-dir", default=None, help="write one Wireshark pcap per test case")
    g.addoption("--verdict-log-level", default="info", help="NR-Lite log level captured per test")


def pytest_configure(config):
    config.addinivalue_line("markers", "tc(id, title, spec): conformance test case metadata")
    setattr(config, _RESULTS_KEY, [])


def _meta(item) -> tuple[str, str, str]:
    m = item.get_closest_marker("tc")
    if m is None:
        return item.name, item.name, ""
    args = list(m.args) + [""] * 3
    return (m.kwargs.get("id", args[0]), m.kwargs.get("title", args[1]), m.kwargs.get("spec", args[2]))


def _pcap_path(request) -> str | None:
    d = request.config.getoption("--verdict-pcap-dir")
    if not d:
        return None
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, re.sub(r"[^A-Za-z0-9_.-]+", "_", _meta(request.node)[0]) + ".pcap")


@pytest.fixture
def ss(request):
    """System Simulator with the UE under test (fresh per test case)."""
    system = SystemSimulator(log_level=request.config.getoption("--verdict-log-level"), pcap_path=_pcap_path(request))
    request.node._verdict_sim = system.sim
    yield system
    system.close()


@pytest.fixture
def testbed_factory(request):
    """Builds full-stack testbeds (UE + gNB + AMF) with optional gNB/AMF configuration."""
    made = []

    def make(**kw):
        kw.setdefault("log_level", request.config.getoption("--verdict-log-level"))
        if not made:
            kw.setdefault("pcap_path", _pcap_path(request))
        tb = Testbed(**kw)
        made.append(tb)
        request.node._verdict_sim = tb.sim
        return tb

    yield make
    for tb in made:
        tb.close()


@pytest.fixture
def ue_emulator(request):
    """Verdict playing the UE towards NR-Lite's gNB and AMF."""
    emu = UeEmulator(log_level=request.config.getoption("--verdict-log-level"), pcap_path=_pcap_path(request))
    request.node._verdict_sim = emu.sim
    yield emu
    emu.sim.stop_pcap()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "setup" and rep.passed:
        return
    if rep.when == "teardown" and rep.passed:
        return
    if item.get_closest_marker("tc") is None:
        return  # only conformance test cases get a verdict; harness unit tests are plain pytest
    tc_id, title, spec = _meta(item)
    sim = getattr(item, "_verdict_sim", None)
    duration = sim.now() if sim is not None else 0
    reason, report = "", ""
    if rep.passed:
        verdict = Verdict.PASS
    elif rep.skipped:
        return
    else:
        exc = call.excinfo.value if call.excinfo else None
        if isinstance(exc, VerdictError):
            verdict = exc.verdict
            reason = exc.reason
            report = format_failure(exc, tc_id, title)
            rep.longrepr = report
        elif isinstance(exc, AssertionError):
            verdict, reason, report = Verdict.FAIL, str(exc).splitlines()[0] if str(exc) else "assertion failed", str(rep.longrepr)
        else:
            verdict, reason, report = Verdict.ERROR, f"{type(exc).__name__}: {exc}", str(rep.longrepr)
        if sim is not None:
            log_tail = [f"{t:>8} {lvl:5} {comp:12} {text}" for t, lvl, comp, text in sim.logs()[-25:]]
            if log_tail:
                report += "\nNR-Lite log (last 25 lines):\n" + "\n".join(log_tail)
                if isinstance(exc, VerdictError):
                    rep.longrepr = report
    getattr(item.config, _RESULTS_KEY).append(CaseResult(item.nodeid, tc_id, title, spec, verdict, duration, reason, report))


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    results: list[CaseResult] = getattr(config, _RESULTS_KEY, [])
    if not results:
        return
    tw = terminalreporter
    tw.section("Verdict")
    width = max(len(r.tc_id) for r in results)
    for r in results:
        colour = {"PASS": {"green": True}, "FAIL": {"red": True}, "INCONC": {"yellow": True}, "ERROR": {"purple": True}}
        tw.write(f"{r.tc_id:<{width}}  ")
        tw.write(f"{r.verdict.value:<6}", **colour[r.verdict.value])
        tw.write(f"  {r.title[:70]}\n")
    counts = {v.value: sum(r.verdict == v for r in results) for v in Verdict}
    tw.write_line("  ".join(f"{k}: {v}" for k, v in counts.items()))
    if config.getoption("--verdict-report"):
        write_html(results, config.getoption("--verdict-report"))
        tw.write_line(f"HTML report: {config.getoption('--verdict-report')}")
    if config.getoption("--verdict-json"):
        write_json(results, config.getoption("--verdict-json"))
