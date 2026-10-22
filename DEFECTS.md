# Defects found in NR-Lite

The first full run of the conformance suite (65 test functions, 67 runs) against NR-Lite
nr-lite@16eba16 gave **62 PASS, 5 FAIL, 0 INCONC**. The five failures came from four defects,
counted by root cause. Each was fixed in NR-Lite with its own commit and a GoogleTest regression
test, and the suite now gives 67 PASS.

| # | Test case(s) | Requirement | Observed | Fix |
|---|---|---|---|---|
| 1 | VD-RRC-004, VD-RRC-008 | TS 24.501 §5.5.1.2.7 b), §5.5.2.2.6: an access attempt barred by the lower layers is not a failed procedure; it is started when barring is alleviated (T302 expiry) | The barred attempt at T3511 expiry was counted as a failure (attempt counter 2), and the registration/de-registration was only retried at the next T3511/T3521 expiry, about 4 s and 10 s late | [nr-lite@bf88079](https://github.com/22ishaq/nr-lite/commit/bf88079) |
| 2 | VD-MM-015 | TS 24.501 §5.5.1.2.5 (#22): the T3346 value IE is used only if REGISTRATION REJECT is integrity protected; otherwise a random 15–30 min value | The UE used the T3346 value (2 min) from an unprotected reject, so an unauthenticated network could set the back-off | [nr-lite@72c77a9](https://github.com/22ishaq/nr-lite/commit/72c77a9) |
| 3 | VD-MM-011 | TS 24.501 §5.4.3.3: the UE answers IDENTITY REQUEST with the requested identity (IMEI) | IDENTITY RESPONSE carried "no identity" | [nr-lite@8753c9a](https://github.com/22ishaq/nr-lite/commit/8753c9a) |
| 4 | VD-MM-020 | TS 24.501 §7.7.2: syntactically incorrect optional IEs are treated as not present | A REGISTRATION ACCEPT with a malformed T3502 IE was rejected with 5GMM STATUS #96 and the registration never completed | [nr-lite@6b17f1d](https://github.com/22ishaq/nr-lite/commit/6b17f1d) |

Counting notes:

* Defects are counted by root cause. VD-RRC-004 and VD-RRC-008 failed for the same reason and
  count once.
* Two of the five failing runs at first included harness bugs, not stack defects: two network-side
  tests checked the stack's state before the last message had been delivered in virtual time.
  Those were fixed in Verdict and are not counted here.
* One further NR-Lite defect (T3520 left running after an aborted registration) was found by
  NR-Lite's own GoogleTest suite, not by Verdict. It is listed in NR-Lite's `docs/DEFECT_LOG.md`.
