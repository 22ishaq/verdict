"""Command-line entry point.

    verdict run [PATH] [--report FILE.html] [--json FILE.json] [--pcap-dir DIR] [-k EXPR]
    verdict list [PATH]          print the test case catalogue (id, spec, title)
    verdict demo                 run one registration against the UE and print the message sequence
"""

from __future__ import annotations

import argparse
import sys


def _run(args: argparse.Namespace) -> int:
    import pytest

    argv = [args.path, "-q", "-p", "verdict.pytest_plugin", "-m", "tc"]
    if args.k:
        argv += ["-k", args.k]
    if args.report:
        argv += ["--verdict-report", args.report]
    if args.json:
        argv += ["--verdict-json", args.json]
    if args.pcap_dir:
        argv += ["--verdict-pcap-dir", args.pcap_dir]
    return int(pytest.main(argv))


def _list(args: argparse.Namespace) -> int:
    import pytest

    class Collector:
        def __init__(self) -> None:
            self.rows: list[tuple[str, str, str]] = []

        def pytest_collection_modifyitems(self, items):
            seen = set()
            for item in items:
                m = item.get_closest_marker("tc")
                if m is None:
                    continue
                tc_id, title, spec = (list(m.args) + ["", "", ""])[:3]
                if tc_id not in seen:
                    seen.add(tc_id)
                    self.rows.append((tc_id, spec, title))

    c = Collector()
    code = pytest.main([args.path, "--collect-only", "-q", "-p", "verdict.pytest_plugin"], plugins=[c])
    width = max((len(r[0]) for r in c.rows), default=4)
    for tc_id, spec, title in c.rows:
        print(f"{tc_id:<{width}}  {spec:<40}  {title}")
    print(f"\n{len(c.rows)} test cases")
    return int(code)


def _demo(_: argparse.Namespace) -> int:
    from verdict.ss import SystemSimulator

    ss = SystemSimulator(log_level="off")
    guti = ss.register()
    print(f"{'t(ms)':>6}  dir  message")
    for e in ss.events:
        print(f"{e['time']:>6}  {e['dir']:3}  {e['summary']}")
    st = ss.ue.state
    print(f"\nUE: {st['mm']}.{st['mm_sub']}, {st['rrc']}, 5G-TMSI 0x{guti['tmsi']:08x}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="verdict", description="Conformance test harness for NR-Lite")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run conformance test cases")
    r.add_argument("path", nargs="?", default="tests")
    r.add_argument("-k", default=None, help="pytest -k expression")
    r.add_argument("--report", default=None, help="HTML report path")
    r.add_argument("--json", default=None, help="JSON verdict file")
    r.add_argument("--pcap-dir", default=None, help="write one Wireshark trace per test case")
    r.set_defaults(fn=_run)
    li = sub.add_parser("list", help="list test cases")
    li.add_argument("path", nargs="?", default="tests")
    li.set_defaults(fn=_list)
    sub.add_parser("demo", help="run a registration and print the message sequence").set_defaults(fn=_demo)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
