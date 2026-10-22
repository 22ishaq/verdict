# Verdict

**A protocol conformance test harness for the [NR-Lite](https://github.com/22ishaq/nr-lite) 5G stack,
written in Python with pytest and C++ bindings (pybind11).** Verdict drives NR-Lite through scripted
scenarios modelled on 3GPP TS 38.523 test cases. It returns a PASS / FAIL / INCONC verdict per
test case, and when a check fails it prints the offending message with the failing field marked.

Its first run against NR-Lite found four defects, all fixed with regression tests (see
[DEFECTS.md](DEFECTS.md)). The full suite runs in CI on every commit.

```
VERDICT: FAIL   VD-MM-020  Registration accept with a syntactically incorrect optional IE
Step:     2: Check: the IE is treated as not present and REGISTRATION COMPLETE is sent
Reason:   the received message does not match the expected template
Expected: RegistrationComplete in UL NAS transport
Received: UL-DCCH ulInformationTransfer [5GMMStatus*]  at t=22 ms
  Mismatching fields:
    - nas.message: expected 'RegistrationComplete', got '5GMMStatus'
  Decoded NAS (integrity+ciphered), failing fields marked »:
    » message = '5GMMStatus'
      body.5gmmCause = 96
Message sequence (most recent last):
          18  DL   DL-DCCH dlInformationTransfer [RegistrationAccept*]   [1: The SS sends REGISTRATION ACCEPT ...]
 >>       22  UL   UL-DCCH ulInformationTransfer [5GMMStatus*]           [2: Check: ... REGISTRATION COMPLETE is sent]
```
<sub>A real report from the first run (abridged). The stack rejected the whole message, when TS 24.501
§7.7.2 says to ignore the malformed optional IE. Fixed in nr-lite@6b17f1d.</sub>

## How it works

```
 pytest + verdict plugin ──► test case ──► SystemSimulator (Python)          NR-Lite (C++)
                                           │ own RRC/NAS codecs              ┌──────────────┐
                                           │ own MILENAGE/KDF/NIA2/NEA2      │ UE: RRC, NAS │
                                           │ templates + verdicts            │ (under test) │
                                           └── _nrlite (pybind11) ──────────►│ gNB, AMF     │
                                               inject DL / receive UL / time  └──────────────┘
```

* **The UE is the device under test.** As in TS 38.523, the System Simulator (SS) plays the gNB and
  AMF. It answers RRCSetupRequest, runs 5G-AKA, activates NAS and AS security, and checks every
  uplink message against a template. Verdict also has a UE emulator, for testing NR-Lite's gNB and
  AMF from the other side, and a full-stack testbed with fault injection (drop, delay, duplicate,
  corrupt).
* **An independent implementation.** The SS never uses NR-Lite's codecs or crypto. Verdict has its
  own UPER and NAS codecs and builds its security on `cryptography`'s AES/CMAC. When the UE's AS
  SecurityModeComplete verifies, the two sides have derived the whole key hierarchy
  (K_AUSF → K_SEAF → K_AMF → K_gNB → K_RRCint) independently and agree. Unit tests also
  cross-check 600 random RRC messages and random crypto inputs against NR-Lite's own implementation.
* **TTCN-3-style templates.** Expected messages are partial structures with matchers (`ANY`, `OMIT`,
  `OneOf`, `Range`, `Pred`). Every mismatch is reported with its path.
* **Verdicts.** A failure inside `ss.preamble()` gives **INCONC** (the UE never reached the initial
  condition). A failed check gives **FAIL**. A crash in the harness itself gives **ERROR**.
* **Deterministic virtual time.** Timers such as T3502 (12 min) or T3346 (up to 30 min) are tested
  in milliseconds of wall-clock time, and the same seed always produces the same bytes.

A test case reads like a TS 38.523 test procedure:

```python
@pytest.mark.tc("VD-RRC-004", "RRC connection reject / T302 barring and retry when barring is alleviated",
                "TS 38.331 §5.3.15, TS 24.501 §5.5.1.2.7 b)")
def test_rrc_reject_wait_time(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"))
    with ss.step(1, "The SS transmits RRCReject with waitTime 16 s"):
        ss.send_dl_ccch(rrc.rrc_reject(16))
    with ss.step(3, "Check: no access attempt while T302 runs"):
        ss.expect_silence(15_900)
    with ss.step(4, "Check: registration is re-attempted when barring is alleviated (T302 expiry)"):
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"), within_ms=600)
```

## Test suite

| Suite | Cases | What it covers |
|---|---|---|
| `tests/conformance/test_rrc.py` | 13 | RRC establishment, T300, RRCReject/T302, AS security mode, release delay, protocol errors, PDCP duplicates |
| `tests/conformance/test_5gmm.py` | 34 | Registration, 5G-AKA (#20/#21/#26/#71), security mode (#23/#24, IMEISV, RINMR), identification, reject causes, T3510/T3511/T3502/T3346, message integrity rules, error handling (#96/#97), replay, out-of-order procedures, de-registration, periodic registration |
| `tests/network/test_network.py` | 11 | gNB and AMF driven by Verdict's UE emulator: malformed input, wrong transaction ids, wrong RES*, AUTS re-sync, integrity rules, replay, admission control |
| `tests/e2e/test_fault_injection.py` | 9 | Full stack with lost, corrupted, delayed and duplicated PDUs; 10 concurrent UEs; determinism |
| `tests/unit/` | 49 | Verdict's own codecs, crypto (TS 35.207 MILENAGE, 128-EIA2/EEA2 vectors), templates, reports, verdict semantics |

That is 67 conformance test runs (65 test functions; one is parametrized over three reject causes)
plus 49 unit tests. `verdict list` prints the full catalogue, and
[docs/TEST_CATALOG.md](docs/TEST_CATALOG.md) has the same list.

The test case IDs (`VD-…`) are Verdict's own. Each case follows the structure of a TS 38.523
test (preamble, numbered stimulus and check steps) and cites the TS 38.331 / TS 24.501 clauses it
checks. The cases are not copies of the 3GPP test procedures.

## Quick start

```bash
git clone --recurse-submodules https://github.com/22ishaq/verdict && cd verdict
python -m venv .venv && . .venv/bin/activate
pip install .                      # builds NR-Lite and the pybind11 module (needs a C++17 compiler + CMake)
verdict demo                       # one registration, printed as a message sequence
verdict run --report report.html --pcap-dir traces
```

`verdict run` is a thin wrapper around `pytest tests`, so `pytest -k MM-0` and the other pytest
options work as usual. `--verdict-pcap-dir` writes one Wireshark-readable trace per test case.

## Layout

```
bindings/nrlite_py.cpp   pybind11 module: simulator control, injection, inspection, NR-Lite codecs/crypto for cross-checks
verdict/codec/           Verdict's own UPER, RRC, NAS and security implementations
verdict/ss.py            System Simulator (gNB + AMF emulation) and generic procedures
verdict/testbed.py       full-stack testbed with fault injection; UE emulator
verdict/templates.py     template matching
verdict/report.py        failure reports, HTML/JSON output
verdict/pytest_plugin.py fixtures, tc marker, verdict mapping, session summary
third_party/nr-lite      the stack under test (git submodule)
```

## License

MIT, see [LICENSE](LICENSE).
