"""5GMM conformance test cases, UE under test (TS 24.501 §5.4, §5.5)."""

import pytest

from verdict.codec import nas, rrc
from verdict.codec import security as sec
from verdict.templates import ANY, OMIT, OneOf, Pred, Range, message

SUCI = {"type": "SUCI", "mcc": "001", "mnc": "01", "protectionSchemeId": 0, "msin": "0000000001"}


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


@pytest.mark.tc("VD-MM-001", "Initial registration / success", "TS 24.501 §5.5.1.2")
def test_initial_registration_success(ss):
    with ss.preamble():
        ss.ue.power_on()
    with ss.step(1, "The UE is made to register"):
        ss.check(ss.ue.register(), "registration not started")
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest", establishmentCause="mo-Signalling"))
        ss.answer_setup()
    with ss.step(2, "Check: REGISTRATION REQUEST (initial, ngKSI 'no key', SUCI, IA2 capability, requested NSSAI)"):
        ss.expect(channel="UL-DCCH", rrc=message("rrcSetupComplete"), nas=message(
            "RegistrationRequest",
            **{"5gsRegistrationType": {"value": 1}, "ngKSI": {"ksi": 7}, "mobileIdentity": SUCI,
               "ueSecurityCapability": {"5G-IA": Pred(lambda v: v & 0x20, "128-5G-IA2 supported")},
               "requestedNSSAI": [{"sst": 1}]}))
        ss.check(ss.ue.timer("T3510") is not None, "T3510 not started")
    with ss.step(3, "Authentication: Check RES* equals XRES*"):
        ss.authenticate()
    with ss.step(4, "Security mode control: Check SECURITY MODE COMPLETE under the new context"):
        ss.nas_security()
        ss.as_security()
    with ss.step(5, "The SS sends REGISTRATION ACCEPT with a 5G-GUTI; Check REGISTRATION COMPLETE"):
        guti = ss.accept()
    with ss.step(6, "Check: 5GMM-REGISTERED.NORMAL-SERVICE, GUTI stored, T3510 stopped"):
        st = ss.ue.state
        ss.check(st["mm"] == "5GMM-REGISTERED" and st["mm_sub"] == "NORMAL-SERVICE", f"{st['mm']}.{st['mm_sub']}")
        ss.check(st["guti"] and st["guti"]["tmsi"] == guti["tmsi"], "assigned 5G-GUTI not stored")
        ss.check(st["timers"]["T3510"] is None, "T3510 still running")


@pytest.mark.tc("VD-MM-002", "Authentication / MAC failure", "TS 24.501 §5.4.1.3.5")
def test_authentication_mac_failure(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS sends AUTHENTICATION REQUEST with a corrupted MAC in AUTN"):
        req = ss.new_challenge()
        autn = bytearray(bytes.fromhex(req["body"]["autn"]))
        autn[-1] ^= 1
        req["body"]["autn"] = autn.hex()
        ss.send_nas(req)
    with ss.step(2, "Check: AUTHENTICATION FAILURE #20 without AUTS, and T3520 running"):
        ss.expect_nas(message("AuthenticationFailure", **{"5gmmCause": 20, "auts": OMIT}))
        ss.check(ss.ue.timer("T3520") is not None, "T3520 not started")


@pytest.mark.tc("VD-MM-003", "Authentication / synch failure and re-synchronisation", "TS 24.501 §5.4.1.3.5, TS 33.102 §6.3.5")
def test_authentication_synch_failure(ss):
    with ss.preamble():
        ss.ue.set_usim_sqn(100)
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS sends AUTHENTICATION REQUEST with a stale SQN (5)"):
        ss.send_nas(ss.new_challenge(sqn=5))
    with ss.step(2, "Check: AUTHENTICATION FAILURE #21 with an AUTS that reveals SQN_MS = 100"):
        pdu = ss.expect_nas(message("AuthenticationFailure", **{"5gmmCause": 21, "auts": ANY}))
        sqn_ms = sec.verify_auts(ss.k, ss.opc, ss.av.rand, bytes.fromhex(pdu.nas.message["body"]["auts"]))
        ss.check(sqn_ms == 100, f"AUTS does not verify or carries SQN_MS {sqn_ms}")
    with ss.step(3, "The SS re-authenticates with SQN_MS + 1; Check: AUTHENTICATION RESPONSE"):
        ss.authenticate(sqn=101)


@pytest.mark.tc("VD-MM-004", "Authentication / AMF separation bit not set", "TS 24.501 §5.4.1.3.5, TS 33.501 §6.1.3.2.0")
def test_authentication_non_5g_vector(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS sends AUTHENTICATION REQUEST whose AUTN has AMF separation bit 0"):
        ss.send_nas(ss.new_challenge(amf=b"\x00\x00"))
    with ss.step(2, "Check: AUTHENTICATION FAILURE #26"):
        ss.expect_nas(message("AuthenticationFailure", **{"5gmmCause": 26}))


@pytest.mark.tc("VD-MM-005", "Authentication / ngKSI already in use", "TS 24.501 §5.4.1.3.5")
def test_authentication_ngksi_in_use(ss):
    with ss.preamble():
        ss.register(release=False)
    with ss.step(1, "The SS re-authenticates using the ngKSI of the current context (0)"):
        ss.send_nas(ss.new_challenge(ngksi=0))
    with ss.step(2, "Check: AUTHENTICATION FAILURE #71"):
        ss.expect_nas(message("AuthenticationFailure", **{"5gmmCause": 71}))


@pytest.mark.tc("VD-MM-006", "Security mode control / replayed UE security capabilities mismatch", "TS 24.501 §5.4.2.5")
def test_smc_capability_mismatch(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
        ss.authenticate()
    with ss.step(1, "The SS sends SECURITY MODE COMMAND replaying different UE security capabilities"):
        ss.security_mode_command(caps={"5G-EA": 0xE0, "5G-IA": 0x60})
    with ss.step(2, "Check: SECURITY MODE REJECT #23, sent without the new context"):
        ss.expect_nas(message("SecurityModeReject", **{"5gmmCause": 23}))
        ss.check(not ss.ue.state["security"]["valid"], "the UE took the rejected context into use")


@pytest.mark.tc("VD-MM-007", "Security mode control / integrity check failure", "TS 24.501 §5.4.2.5")
def test_smc_integrity_failure(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
        ss.authenticate()
    with ss.step(1, "The SS sends SECURITY MODE COMMAND with an invalid MAC"):
        ss.security_mode_command(corrupt_mac=True)
    with ss.step(2, "Check: SECURITY MODE REJECT #24"):
        ss.expect_nas(message("SecurityModeReject", **{"5gmmCause": 24}))


@pytest.mark.tc("VD-MM-008", "Security mode control / IMEISV request", "TS 24.501 §5.4.2.3")
def test_smc_imeisv_request(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
        ss.authenticate()
    with ss.step(1, "The SS sends SECURITY MODE COMMAND with IMEISV request"):
        ss.security_mode_command(imeisv_request=True)
    with ss.step(2, "Check: SECURITY MODE COMPLETE carries the 16-digit IMEISV"):
        ss.expect_nas(message("SecurityModeComplete", imeisv={"type": "IMEISV",
                                                              "digits": Pred(lambda d: len(d) == 16, "16 digits")}))


@pytest.mark.tc("VD-MM-009", "Security mode control / retransmission of the initial NAS message (RINMR)", "TS 24.501 §5.4.2.3")
def test_smc_rinmr(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
        ss.authenticate()
    with ss.step(1, "The SS sends SECURITY MODE COMMAND with RINMR set"):
        ss.security_mode_command(additional=0x02)
    with ss.step(2, "Check: SECURITY MODE COMPLETE contains the complete REGISTRATION REQUEST"):
        pdu = ss.expect_nas(message("SecurityModeComplete", nasMessageContainer=ANY))
        inner = nas.decode(bytes.fromhex(pdu.nas.message["body"]["nasMessageContainer"])).message
        ss.check(inner["message"] == "RegistrationRequest", f"container holds {inner['message']}")


@pytest.mark.tc("VD-MM-010", "Identification / SUCI requested before security", "TS 24.501 §5.4.3, §4.4.4.2")
def test_identification_suci(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS sends an unprotected IDENTITY REQUEST for the SUCI"):
        ss.send_nas(nas.plain("IdentityRequest", identityType=1))
    with ss.step(2, "Check: IDENTITY RESPONSE with the SUCI (null scheme)"):
        ss.expect_nas(message("IdentityResponse", mobileIdentity=SUCI))


@pytest.mark.tc("VD-MM-011", "Identification / IMEI requested after security", "TS 24.501 §5.4.3.3, TS 23.003 §6.2")
def test_identification_imei(ss):
    with ss.preamble():
        ss.register(release=False)
    with ss.step(1, "The SS sends a protected IDENTITY REQUEST for the IMEI"):
        ss.send_nas(nas.plain("IdentityRequest", identityType=3))
    with ss.step(2, "Check: IDENTITY RESPONSE with a 15-digit IMEI (valid check digit, same TAC/SNR as the IMEISV)"):
        pdu = ss.expect_nas(message("IdentityResponse", mobileIdentity={"type": "IMEI", "digits": Pred(
            lambda d: len(d) == 15 and _luhn_ok(d), "15 digits with a valid Luhn check digit")}))
        ss.check(pdu.nas.message["body"]["mobileIdentity"]["digits"][:14] == "35349006987331",
                 "IMEI does not share TAC and serial number with the IMEISV")


@pytest.mark.tc("VD-MM-012", "Identification / unprotected IMEISV request is not answered", "TS 24.501 §4.4.4.2")
def test_identification_unprotected_imeisv_ignored(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS sends an unprotected IDENTITY REQUEST for the IMEISV"):
        ss.send_nas(nas.plain("IdentityRequest", identityType=5))
    with ss.step(2, "Check: the UE does not answer"):
        ss.expect_silence(1000)


@pytest.mark.parametrize("cause", [3, 6, 7])
@pytest.mark.tc("VD-MM-013", "Registration reject / #3 #6 #7: USIM invalid, no further attempts", "TS 24.501 §5.5.1.2.5")
def test_registration_reject_usim_invalid(ss, cause):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, f"The SS sends REGISTRATION REJECT #{cause}"):
        ss.send_nas(nas.registration_reject(cause))
        ss.release()
    with ss.step(2, "Check: 5GMM-DEREGISTERED and no further registration attempt (also not on request)"):
        ss.check(ss.ue.state["mm"] == "5GMM-DEREGISTERED", ss.ue.state["mm"])
        ss.ue.register()
        ss.expect_silence(13 * 60 * 1000)


@pytest.mark.tc("VD-MM-014", "Registration reject #22 (integrity protected) / back-off with the signalled T3346",
                "TS 24.501 §5.5.1.2.5")
def test_registration_reject_congestion_protected(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
        ss.authenticate()
        ss.nas_security()
    with ss.step(1, "The SS sends an integrity protected REGISTRATION REJECT #22 with T3346 = 2 min"):
        ss.send_nas(nas.registration_reject(22, {"unit": 1, "value": 2}))
        ss.release()
    with ss.step(2, "Check: T3346 runs for 2 min and the UE does not attempt registration meanwhile"):
        t = ss.ue.timer("T3346")
        ss.check(t is not None and 119_000 <= t <= 120_000, f"T3346 remaining {t}")
        ss.expect_silence(119_000)
    with ss.step(3, "Check: registration is attempted when T3346 expires"):
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"), within_ms=2_000)


@pytest.mark.tc("VD-MM-015", "Registration reject #22 (not integrity protected) / T3346 value IE not trusted",
                "TS 24.501 §5.5.1.2.5")
def test_registration_reject_congestion_unprotected(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS sends an unprotected REGISTRATION REJECT #22 with T3346 = 2 min"):
        ss.send_nas(nas.registration_reject(22, {"unit": 1, "value": 2}))
        ss.release()
    with ss.step(2, "Check: T3346 is started with a random value from the default range (15-30 min)"):
        t = ss.ue.timer("T3346")
        ss.check(t is not None and 14 * 60_000 <= t <= 30 * 60_000, f"T3346 remaining {t} ms")


@pytest.mark.tc("VD-MM-016", "Registration reject with another cause / attempt counter and T3511", "TS 24.501 §5.5.1.2.7")
def test_registration_reject_other_cause(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS sends REGISTRATION REJECT #111"):
        ss.send_nas(nas.registration_reject(111))
        ss.release()
    with ss.step(2, "Check: attempt counter 1, 5GMM-DEREGISTERED.ATTEMPTING-REGISTRATION, retry after T3511 (10 s)"):
        st = ss.ue.state
        ss.check(st["attempt_counter"] == 1 and st["mm_sub"] == "ATTEMPTING-REGISTRATION",
                 f"counter {st['attempt_counter']}, {st['mm_sub']}")
        ss.expect_silence(9_800)
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"), within_ms=400)


@pytest.mark.tc("VD-MM-017", "Abnormal case / T3510 expiry and retry", "TS 24.501 §5.5.1.2.7 c)")
def test_t3510_expiry(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS does not answer the REGISTRATION REQUEST"):
        ss.advance(15_000)
    with ss.step(2, "Check: T3510 expired, the NAS signalling connection was released locally"):
        st = ss.ue.state
        ss.check(st["rrc"] == "RRC_IDLE", f"UE in {st['rrc']}")
        ss.check(st["attempt_counter"] == 1, f"attempt counter {st['attempt_counter']}")
    with ss.step(3, "Check: registration is retried when T3511 (10 s) expires"):
        ss.expect_silence(9_900)
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"), within_ms=300)


@pytest.mark.tc("VD-MM-018", "Abnormal case / fifth failure starts T3502", "TS 24.501 §5.5.1.2.7")
def test_fifth_failure_t3502(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
    with ss.step(1, "Five registration attempts are left unanswered (T300 expiries)"):
        for attempt in range(5):
            ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"), within_ms=12_000,
                      what=f"RRCSetupRequest (attempt {attempt + 1})")
    with ss.step(2, "Check: after the fifth failure the UE waits T3502 (12 min) before retrying"):
        ss.advance(1_100)
        ss.check(ss.ue.state["attempt_counter"] == 5, f"attempt counter {ss.ue.state['attempt_counter']}")
        ss.check(ss.ue.timer("T3502") is not None, "T3502 not running")
        ss.expect_silence(12 * 60_000 - 1_000)
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"), within_ms=2_000)


@pytest.mark.tc("VD-MM-019", "Registration accept not integrity protected is discarded", "TS 24.501 §4.4.4.2")
def test_unprotected_registration_accept_discarded(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
        ss.authenticate()
        ss.nas_security()
        ss.as_security()
    with ss.step(1, "The SS sends REGISTRATION ACCEPT without integrity protection"):
        ss.send_nas(nas.registration_accept({"type": "5G-GUTI", "mcc": "001", "mnc": "01", "amfRegionId": 1,
                                             "amfSetId": 1, "amfPointer": 1, "tmsi": 9}), protection="plain")
    with ss.step(2, "Check: no REGISTRATION COMPLETE and the UE is still registering"):
        ss.expect_silence(1_000)
        ss.check(ss.ue.state["mm"] == "5GMM-REGISTERED-INITIATED", ss.ue.state["mm"])
    with ss.step(3, "Check: the same message, protected, completes the registration"):
        ss.accept()


@pytest.mark.tc("VD-MM-020", "Registration accept with a syntactically incorrect optional IE", "TS 24.501 §7.7.2")
def test_registration_accept_bad_optional_ie(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
        ss.authenticate()
        ss.nas_security()
        ss.as_security()
    with ss.step(1, "The SS sends REGISTRATION ACCEPT whose T3502 value IE has length 2 instead of 1"):
        ss.accept(extra_ies=bytes([0x16, 0x02, 0x21, 0x21]), expect_complete=False)
    with ss.step(2, "Check: the IE is treated as not present and REGISTRATION COMPLETE is sent"):
        ss.expect_nas(message("RegistrationComplete"))


@pytest.mark.tc("VD-MM-021", "Registration accept with an unknown optional IE", "TS 24.501 §7.6.1")
def test_registration_accept_unknown_ie(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
        ss.authenticate()
        ss.nas_security()
        ss.as_security()
    with ss.step(1, "The SS sends REGISTRATION ACCEPT with an unknown TLV IE (IEI 0x1C) and TLV-E IE (0x7C)"):
        ss.accept(extra_ies=bytes.fromhex("1c03aabbcc" "7c0002dead"), expect_complete=False)
    with ss.step(2, "Check: REGISTRATION COMPLETE"):
        ss.expect_nas(message("RegistrationComplete"))


@pytest.mark.tc("VD-MM-022", "Unknown message type / 5GMM STATUS #97", "TS 24.501 §7.4")
def test_unknown_message_type(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS sends a 5GMM message with message type 0x99"):
        ss.send_nas(b"\x7e\x00\x99", summary="message type 0x99")
    with ss.step(2, "Check: 5GMM STATUS #97"):
        ss.expect_nas(message("5GMMStatus", **{"5gmmCause": 97}))


@pytest.mark.tc("VD-MM-023", "Missing mandatory IE / 5GMM STATUS #96", "TS 24.501 §7.5.1")
def test_missing_mandatory_ie(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS sends AUTHENTICATION REQUEST without the mandatory ABBA IE"):
        ss.send_nas(b"\x7e\x00\x56\x00", summary="AuthenticationRequest without ABBA")
    with ss.step(2, "Check: 5GMM STATUS #96"):
        ss.expect_nas(message("5GMMStatus", **{"5gmmCause": 96}))


@pytest.mark.tc("VD-MM-024", "Replayed NAS message is discarded", "TS 24.501 §4.4.3.2, TS 33.501 §6.4.3")
def test_replayed_nas_message(ss):
    with ss.preamble():
        ss.register(release=False)
    with ss.step(1, "The SS sends a protected IDENTITY REQUEST (IMEISV) and the UE answers"):
        pdu = ss.send_nas(nas.plain("IdentityRequest", identityType=5))
        ss.expect_nas(message("IdentityResponse", mobileIdentity={"type": "IMEISV"}))
    with ss.step(2, "The SS replays the identical NAS PDU (same NAS COUNT)"):
        ss.send_dl_dcch(rrc.dl_information_transfer(ss.next_txid(), pdu), "dlInformationTransfer [IdentityRequest*] (replay)")
    with ss.step(3, "Check: the replayed message is not answered"):
        ss.expect_silence(1_000)


@pytest.mark.tc("VD-MM-025", "Out of order / SECURITY MODE COMMAND before authentication", "TS 24.501 §5.4.2.5")
def test_smc_before_authentication(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS sends SECURITY MODE COMMAND for a context the UE never authenticated"):
        ss.kamf = bytes(32)
        ss.security_mode_command()
    with ss.step(2, "Check: SECURITY MODE REJECT #24"):
        ss.expect_nas(message("SecurityModeReject", **{"5gmmCause": 24}))


@pytest.mark.tc("VD-MM-026", "Out of order / protected REGISTRATION ACCEPT before security mode control",
                "TS 24.501 §4.4.4.2")
def test_registration_accept_before_smc(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
        ss.authenticate()
    with ss.step(1, "The SS sends REGISTRATION ACCEPT protected with a context the UE has not taken into use"):
        ss.nas_ctx = sec.NasContext(ss.kamf, 0, 2, 0)
        ss.send_nas(nas.registration_accept(None))
    with ss.step(2, "Check: the message is discarded"):
        ss.expect_silence(1_000)
        ss.check(ss.ue.state["mm"] == "5GMM-REGISTERED-INITIATED", ss.ue.state["mm"])


@pytest.mark.tc("VD-MM-027", "Out of order / AS SecurityModeCommand before NAS security", "TS 38.331 §5.3.4.3")
def test_as_smc_before_nas_smc(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
        ss.authenticate()
    with ss.step(1, "The SS sends RRC SecurityModeCommand before NAS security is active"):
        txid = ss.next_txid()
        ss.pdcp.tx_int = bytes(16)
        ss.send_dl_dcch(rrc.security_mode_command(txid))
    with ss.step(2, "Check: SecurityModeFailure"):
        ss.expect(channel="UL-DCCH", rrc=message("securityModeFailure", **{"rrc-TransactionIdentifier": txid}))


@pytest.mark.tc("VD-MM-028", "Authentication reject / USIM invalid", "TS 24.501 §5.4.1.3.5")
def test_authentication_reject(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS sends AUTHENTICATION REJECT"):
        ss.send_nas(nas.plain("AuthenticationReject"))
        ss.advance(100)
    with ss.step(2, "Check: the UE deregisters, releases the connection and makes no further attempt"):
        st = ss.ue.state
        ss.check(st["mm"] == "5GMM-DEREGISTERED", st["mm"])
        ss.check(st["rrc"] == "RRC_IDLE", f"UE in {st['rrc']}")
        ss.ue.register()
        ss.expect_silence(13 * 60_000)


@pytest.mark.tc("VD-MM-029", "UE-initiated de-registration / normal", "TS 24.501 §5.5.2.2")
def test_deregistration_normal(ss):
    with ss.preamble():
        guti = ss.register()
    with ss.step(1, "The UE is made to de-register"):
        ss.check(ss.ue.deregister(), "de-registration not started")
    with ss.step(2, "Check: RRC connection set up with the 5G-S-TMSI and an integrity protected DEREGISTRATION REQUEST"):
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest", **{"ue-Identity": {"ng-5G-S-TMSI-Part1": ANY}}))
        ss.answer_setup()
        pdu = ss.expect(channel="UL-DCCH", rrc=message("rrcSetupComplete"), nas=message(
            "DeregistrationRequest(UE originating)", switchOff=0, mobileIdentity={"type": "5G-GUTI", "tmsi": guti["tmsi"]}))
        ss.check(pdu.nas.protection == "integrity", f"DEREGISTRATION REQUEST protection: {pdu.nas.protection}")
        ss.check(ss.ue.timer("T3521") is not None, "T3521 not started")
    with ss.step(3, "The SS sends DEREGISTRATION ACCEPT; Check: 5GMM-DEREGISTERED and T3521 stopped"):
        ss.send_nas(nas.plain("DeregistrationAccept(UE originating)"))
        ss.advance(10)
        st = ss.ue.state
        ss.check(st["mm"] == "5GMM-DEREGISTERED" and st["timers"]["T3521"] is None, f"{st['mm']}")


@pytest.mark.tc("VD-MM-030", "UE-initiated de-registration / T3521 retransmission", "TS 24.501 §5.5.2.2.6 c)")
def test_t3521_retransmission(ss):
    with ss.preamble():
        ss.register(release=False)
    with ss.step(1, "The UE is made to de-register; the SS never answers"):
        ss.ue.deregister()
        ss.expect_nas(message("DeregistrationRequest(UE originating)"))
    with ss.step(2, "Check: four retransmissions at 15 s intervals"):
        for i in range(4):
            ss.expect_silence(14_900)
            ss.expect_nas(message("DeregistrationRequest(UE originating)"), within_ms=200)
    with ss.step(3, "Check: on the fifth expiry the procedure is aborted (5GMM-DEREGISTERED)"):
        ss.advance(15_100)
        ss.check(ss.ue.state["mm"] == "5GMM-DEREGISTERED", ss.ue.state["mm"])


@pytest.mark.tc("VD-MM-031", "UE-initiated de-registration / switch off", "TS 24.501 §5.5.2.2.1")
def test_deregistration_switch_off(ss):
    with ss.preamble():
        ss.register(release=False)
    with ss.step(1, "The UE is made to de-register for switch off"):
        ss.ue.deregister(switch_off=True)
    with ss.step(2, "Check: DEREGISTRATION REQUEST with switch off, and the UE does not wait for an accept"):
        ss.expect_nas(message("DeregistrationRequest(UE originating)", switchOff=1))
        ss.check(ss.ue.state["mm"] == "5GMM-DEREGISTERED", ss.ue.state["mm"])
        ss.check(ss.ue.timer("T3521") is None, "T3521 started for a switch-off de-registration")


@pytest.mark.tc("VD-MM-032", "Periodic registration / T3512 expiry", "TS 24.501 §5.3.7, §5.5.1.3")
def test_periodic_registration(ss):
    with ss.preamble():
        guti = ss.register(t3512={"unit": 3, "value": 5})
    with ss.step(1, "Check: T3512 runs with the value from REGISTRATION ACCEPT (10 s)"):
        t = ss.ue.timer("T3512")
        ss.check(t is not None and 9_000 <= t <= 10_000, f"T3512 remaining {t}")
    with ss.step(2, "Check: on expiry, a periodic REGISTRATION REQUEST with the 5G-GUTI, integrity protected"):
        ss.advance(10_000)
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"))
        ss.answer_setup()
        pdu = ss.expect(channel="UL-DCCH", rrc=message("rrcSetupComplete"), nas=message("RegistrationRequest", **{
            "5gsRegistrationType": {"value": 3}, "mobileIdentity": {"type": "5G-GUTI", "tmsi": guti["tmsi"]}}))
        ss.check(pdu.nas.protection == "integrity" and pdu.nas.integrity_ok, "not integrity protected with the stored context")
    with ss.step(3, "The SS accepts without re-authentication; Check: REGISTRATION COMPLETE"):
        ss.as_security()
        ss.accept()
