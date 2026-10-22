# Test case catalogue

Generated with `verdict list`. Each case cites the clauses it checks; IDs are Verdict's own.

| ID | Specification | Title |
|---|---|---|
| VD-MM-001 | TS 24.501 §5.5.1.2 | Initial registration / success |
| VD-MM-002 | TS 24.501 §5.4.1.3.5 | Authentication / MAC failure |
| VD-MM-003 | TS 24.501 §5.4.1.3.5, TS 33.102 §6.3.5 | Authentication / synch failure and re-synchronisation |
VD-MM-004   TS 24.501 §5.4.1.3.5, TS 33.501 §6.1.3.2.0  Authentication / AMF separation bit not set
| VD-MM-005 | TS 24.501 §5.4.1.3.5 | Authentication / ngKSI already in use |
| VD-MM-006 | TS 24.501 §5.4.2.5 | Security mode control / replayed UE security capabilities mismatch |
| VD-MM-007 | TS 24.501 §5.4.2.5 | Security mode control / integrity check failure |
| VD-MM-008 | TS 24.501 §5.4.2.3 | Security mode control / IMEISV request |
| VD-MM-009 | TS 24.501 §5.4.2.3 | Security mode control / retransmission of the initial NAS message (RINMR) |
| VD-MM-010 | TS 24.501 §5.4.3, §4.4.4.2 | Identification / SUCI requested before security |
| VD-MM-011 | TS 24.501 §5.4.3.3, TS 23.003 §6.2 | Identification / IMEI requested after security |
| VD-MM-012 | TS 24.501 §4.4.4.2 | Identification / unprotected IMEISV request is not answered |
| VD-MM-013 | TS 24.501 §5.5.1.2.5 | Registration reject / #3 #6 #7: USIM invalid, no further attempts |
| VD-MM-014 | TS 24.501 §5.5.1.2.5 | Registration reject #22 (integrity protected) / back-off with the signalled T3346 |
| VD-MM-015 | TS 24.501 §5.5.1.2.5 | Registration reject #22 (not integrity protected) / T3346 value IE not trusted |
| VD-MM-016 | TS 24.501 §5.5.1.2.7 | Registration reject with another cause / attempt counter and T3511 |
| VD-MM-017 | TS 24.501 §5.5.1.2.7 c) | Abnormal case / T3510 expiry and retry |
| VD-MM-018 | TS 24.501 §5.5.1.2.7 | Abnormal case / fifth failure starts T3502 |
| VD-MM-019 | TS 24.501 §4.4.4.2 | Registration accept not integrity protected is discarded |
| VD-MM-020 | TS 24.501 §7.7.2 | Registration accept with a syntactically incorrect optional IE |
| VD-MM-021 | TS 24.501 §7.6.1 | Registration accept with an unknown optional IE |
| VD-MM-022 | TS 24.501 §7.4 | Unknown message type / 5GMM STATUS #97 |
| VD-MM-023 | TS 24.501 §7.5.1 | Missing mandatory IE / 5GMM STATUS #96 |
| VD-MM-024 | TS 24.501 §4.4.3.2, TS 33.501 §6.4.3 | Replayed NAS message is discarded |
| VD-MM-025 | TS 24.501 §5.4.2.5 | Out of order / SECURITY MODE COMMAND before authentication |
| VD-MM-026 | TS 24.501 §4.4.4.2 | Out of order / protected REGISTRATION ACCEPT before security mode control |
| VD-MM-027 | TS 38.331 §5.3.4.3 | Out of order / AS SecurityModeCommand before NAS security |
| VD-MM-028 | TS 24.501 §5.4.1.3.5 | Authentication reject / USIM invalid |
| VD-MM-029 | TS 24.501 §5.5.2.2 | UE-initiated de-registration / normal |
| VD-MM-030 | TS 24.501 §5.5.2.2.6 c) | UE-initiated de-registration / T3521 retransmission |
| VD-MM-031 | TS 24.501 §5.5.2.2.1 | UE-initiated de-registration / switch off |
| VD-MM-032 | TS 24.501 §5.3.7, §5.5.1.3 | Periodic registration / T3512 expiry |
| VD-RRC-001 | TS 38.331 §5.3.3 | RRC connection establishment / success |
| VD-RRC-002 | TS 38.331 §5.3.3.3, §5.3.3.4 | RRC connection establishment / 5G-S-TMSI split into part 1 and part 2 |
VD-RRC-003  TS 38.331 §5.3.3.7, TS 24.501 §5.5.1.2.7  RRC connection establishment / T300 expiry
VD-RRC-004  TS 38.331 §5.3.15, TS 24.501 §5.5.1.2.7 b)  RRC connection reject / T302 barring and retry when barring is alleviated
| VD-RRC-005 | TS 38.331 §5.3.4 | Initial AS security activation / success |
| VD-RRC-006 | TS 38.331 §5.3.4.3 | Initial AS security activation / SecurityModeCommand integrity failure |
| VD-RRC-007 | TS 38.331 §5.3.8.3 | RRC release / actions delayed by 60 ms |
VD-RRC-008  TS 38.331 §5.3.8.3, TS 24.501 §5.5.2.2.6  RRC release with waitTime / access barred until T302 expiry
| VD-RRC-009 | TS 38.331 §10.4 | RRC connection establishment / DL-CCCH abstract syntax error is ignored |
| VD-RRC-010 | TS 38.331 §5.3.3.4 | Unsolicited RRCSetup in RRC_IDLE is ignored |
| VD-RRC-011 | TS 38.331 §5.3.4, TS 33.501 §6.5 | Integrity failure on DL-DCCH after AS security / message not processed |
| VD-RRC-012 | TS 38.323 §5.2.2.1 | Duplicated DL-DCCH PDU is delivered only once |
| VD-RRC-013 | TS 38.331 §5.3.3.4 | RRCSetup without SRB1 / UE does not use DCCH |
VD-E2E-001  TS 38.331 §5.3.3.7, TS 24.501 §5.5.1.2.7  Lost RRCSetup / recovery through T300 and T3511
| VD-E2E-002 | TS 24.501 §5.5.1.2.8 | Lost REGISTRATION COMPLETE / T3550 retransmission |
| VD-E2E-003 | TS 24.501 §5.4.1.3.7 | Lost AUTHENTICATION RESPONSE / T3560 and SQN re-synchronisation |
| VD-E2E-004 | TS 24.501 §5.4.2.5 | Corrupted NAS SECURITY MODE COMMAND / reject, abort, retry |
| VD-E2E-005 | TS 38.331 §5.3.4.3 | Corrupted RRC SecurityModeCommand / failure, abort, retry |
| VD-E2E-006 | TS 38.323 §5.2.2 | Reordered downlink / AS SMC delayed behind later traffic |
| VD-E2E-007 | TS 38.323 §5.2.2.1 | Duplicated downlink PDCP PDU is discarded |
| VD-E2E-008 | TS 24.501 §5.5.1.2 | Ten UEs register concurrently |
| VD-E2E-009 | determinism | Same seed reproduces the same trace bit for bit |
| VD-NW-001 | TS 24.501 §5.5.1.2, TS 38.331 §5.3 | Registration of an independent UE implementation |
| VD-NW-002 | TS 38.331 §10.4 | gNB ignores a truncated RRCSetupRequest |
| VD-NW-003 | TS 38.331 §6.2.2 (spare bits) | gNB accepts RRCSetupRequest with the spare bit set |
| VD-NW-004 | TS 38.331 §5.3.3 | gNB ignores RRCSetupComplete with a wrong transaction identifier |
| VD-NW-005 | TS 38.331 §10.4 | gNB survives undecodable UL-DCCH and keeps serving the UE |
| VD-NW-006 | TS 33.501 §6.1.3.2.2 | AMF rejects a wrong RES* |
| VD-NW-007 | TS 33.102 §6.3.5 | AMF re-synchronises on AUTS |
| VD-NW-008 | TS 24.501 §4.4.4.3 | AMF discards an unprotected REGISTRATION COMPLETE after security activation |
| VD-NW-009 | TS 33.501 §6.4.3 | AMF discards a replayed SECURITY MODE COMPLETE |
| VD-NW-010 | TS 24.501 §5.5.1.2.2 | AMF does not register a UE that omits its security capabilities |
| VD-NW-011 | TS 38.331 §5.3.15 | gNB admission control / RRCReject with waitTime |
