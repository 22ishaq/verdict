"""Human-readable verdict reports.

A failure report shows, in order: the verdict and the step that failed, what was expected, the
message that was received instead with the mismatching fields, the decoded message with failing
fields marked, a hex dump with the failing bytes bracketed, and the message sequence leading up to
the failure.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field

from verdict.verdicts import Verdict, VerdictError

MSC_TAIL = 14


@dataclass
class CaseResult:
    nodeid: str
    tc_id: str
    title: str
    spec: str
    verdict: Verdict
    duration_ms: int = 0
    reason: str = ""
    report: str = ""
    events: list = field(default_factory=list)


def hexdump(data: bytes, highlight: list[tuple[int, int]] | None = None, width: int = 16) -> list[str]:
    """Hex dump with highlighted byte ranges shown as [xx]."""
    marked = set()
    for start, end in highlight or []:
        marked.update(range(start, max(end, start + 1)))
    lines = []
    for off in range(0, len(data), width):
        cells = []
        for i in range(off, min(off + width, len(data))):
            cells.append(f"[{data[i]:02x}]" if i in marked else f" {data[i]:02x} ")
        lines.append(f"    {off:04x} " + "".join(cells))
    return lines or ["    (empty)"]


def _flatten(d, prefix=""):
    if isinstance(d, dict):
        for k, v in d.items():
            yield from _flatten(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(d, list):
        for i, v in enumerate(d):
            yield from _flatten(v, f"{prefix}[{i}]")
    else:
        yield prefix, d


def _decoded_lines(msg: dict, bad: set[str], indent: str = "    ") -> list[str]:
    out = []
    for path, value in _flatten(msg):
        mark = "»" if any(path == b or path.startswith(b + ".") or path.startswith(b + "[") for b in bad) else " "
        out.append(f"{indent}{mark} {path} = {value!r}")
    return out


def _bit_spans_to_bytes(spans: dict, paths: set[str]) -> list[tuple[int, int]]:
    out = []
    for p, (s, e) in spans.items():
        if any(p == b or b.startswith(p + ".") or p.startswith(b + ".") for b in paths):
            out.append((s // 8, (e + 7) // 8))
    return out


def format_failure(err: VerdictError, tc_id: str = "", title: str = "") -> str:
    lines = [f"VERDICT: {err.verdict.value}" + (f"   {tc_id}  {title}" if tc_id else "")]
    if err.step:
        lines.append(f"Step:     {err.step}")
    lines.append(f"Reason:   {err.reason}")
    if err.expected:
        lines.append(f"Expected: {err.expected}")
    pdu = err.pdu
    if pdu is not None:
        lines.append(f"Received: {pdu.summary()}  at t={pdu.time} ms")
        if err.mismatches:
            lines.append("  Mismatching fields:")
            lines += [f"    - {m}" for m in err.mismatches]
        bad_rrc = {m.path.removeprefix("rrc.") for m in err.mismatches if m.path.startswith("rrc")}
        bad_nas = {m.path.removeprefix("nas.") for m in err.mismatches if m.path.startswith("nas")}
        if pdu.rrc is not None:
            lines.append(f"  Decoded RRC ({pdu.channel}), failing fields marked »:")
            lines += _decoded_lines(pdu.rrc, bad_rrc)
        if pdu.nas is not None and pdu.nas.message is not None:
            lines.append(f"  Decoded NAS ({pdu.nas.protection}), failing fields marked »:")
            lines += _decoded_lines(pdu.nas.message, bad_nas)
        if pdu.nas is not None and pdu.nas.plain:
            lines.append("  NAS PDU hex, failing bytes in [..]:")
            lines += hexdump(pdu.nas.plain, _bit_spans_to_bytes({k: (s * 8, e * 8) for k, (s, e) in pdu.nas.spans.items()},
                                                                bad_nas))
        lines.append("  RRC PDU hex" + (", failing bytes in [..]:" if bad_rrc else ":"))
        lines += hexdump(pdu.rrc_bytes, _bit_spans_to_bytes(pdu.rrc_spans, bad_rrc))
        if pdu.decode_error:
            lines.append(f"  Decode error: {pdu.decode_error}")
    if err.capture:
        lines.append("Message sequence (most recent last):")
        lines.append(f"    {'t(ms)':>8}  {'dir':4} message")
        events = err.capture[-MSC_TAIL:]
        for ev in events:
            arrow = ">>" if pdu is not None and ev.get("pdu") is pdu else "  "
            step = f"   [{ev['step']}]" if ev.get("step") else ""
            lines.append(f" {arrow} {ev['time']:>8}  {ev['dir']:4} {ev['summary']}{step}")
    return "\n".join(lines)


def write_json(results: list[CaseResult], path: str) -> None:
    with open(path, "w") as fh:
        json.dump([{k: (v.value if isinstance(v, Verdict) else v) for k, v in r.__dict__.items() if k != "events"}
                   for r in results], fh, indent=2)


def write_html(results: list[CaseResult], path: str) -> None:
    counts = {v: sum(1 for r in results if r.verdict == v) for v in Verdict}
    colour = {Verdict.PASS: "#0ca30c", Verdict.FAIL: "#d03b3b", Verdict.INCONC: "#c98500", Verdict.ERROR: "#6250d6"}
    rows = []
    for r in results:
        detail = f"<details><summary>details</summary><pre>{html.escape(r.report)}</pre></details>" if r.report else ""
        rows.append(
            f"<tr><td>{html.escape(r.tc_id)}</td><td>{html.escape(r.title)}</td><td>{html.escape(r.spec)}</td>"
            f"<td><span class='v' style='background:{colour[r.verdict]}'>{r.verdict.value}</span></td>"
            f"<td class='num'>{r.duration_ms}</td><td>{html.escape(r.reason)}{detail}</td></tr>")
    summary = " · ".join(f"{v.value}: {counts[v]}" for v in Verdict)
    doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>Verdict report</title>
<style>
body{{font:14px/1.45 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;margin:24px;background:#fcfcfb;color:#0b0b0b}}
table{{border-collapse:collapse;width:100%}} th,td{{border-bottom:1px solid #e4e3df;padding:6px 8px;text-align:left;vertical-align:top}}
th{{color:#52514e;font-weight:600}} .num{{text-align:right;font-variant-numeric:tabular-nums}}
.v{{color:#fff;border-radius:4px;padding:1px 6px;font-weight:600;font-size:12px}}
pre{{background:#f4f3f0;padding:8px;overflow:auto;font-size:12px}}
</style></head><body><h1>Verdict report</h1><p>{summary}</p>
<table><tr><th>TC</th><th>Title</th><th>Spec</th><th>Verdict</th><th>Virtual time (ms)</th><th>Reason</th></tr>
{''.join(rows)}</table></body></html>"""
    with open(path, "w") as fh:
        fh.write(doc)
