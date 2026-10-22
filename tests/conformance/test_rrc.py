"""RRC conformance test cases, UE under test (TS 38.331 §5.3).

Structured like TS 38.523-1 RRC test cases: a preamble that brings the UE into the initial
condition, then numbered steps that either stimulate the UE or check its response.
"""

import pytest

from verdict.codec import nas, rrc
from verdict.templates import ANY, OMIT, Range, message

MAX39 = (1 << 39) - 1


@pytest.mark.tc("VD-RRC-001", "RRC connection establishment / success", "TS 38.331 §5.3.3")
def test_rrc_connection_establishment_success(ss):
    with ss.preamble():
        ss.ue.power_on()
    with ss.step(1, "The UE is made to initiate registration"):
        ss.check(ss.ue.register(), "the UE did not start registration")
    with ss.step(2, "Check: RRCSetupRequest with a 39-bit randomValue and cause mo-Signalling"):
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest", **{
            "ue-Identity": {"randomValue": Range(0, MAX39)}, "establishmentCause": "mo-Signalling"}))
    with ss.step(3, "Check: T300 is running"):
        ss.check(ss.ue.timer("T300") is not None, "T300 is not running after RRCSetupRequest")
    with ss.step(4, "The SS transmits RRCSetup (rrc-TransactionIdentifier 2)"):
        ss.send_dl_ccch(rrc.rrc_setup(2))
    with ss.step(5, "Check: RRCSetupComplete echoes the transaction identifier and carries REGISTRATION REQUEST"):
        ss.expect(channel="UL-DCCH",
                  rrc=message("rrcSetupComplete", **{"rrc-TransactionIdentifier": 2, "selectedPLMN-Identity": 1,
                                                     "ng-5G-S-TMSI-Value": OMIT}),
                  nas=message("RegistrationRequest"))
    with ss.step(6, "Check: the UE is in RRC_CONNECTED and T300 is stopped"):
        st = ss.ue.state
        ss.check(st["rrc"] == "RRC_CONNECTED", f"UE is in {st['rrc']}")
        ss.check(st["timers"]["T300"] is None, "T300 still running")


@pytest.mark.tc("VD-RRC-002", "RRC connection establishment / 5G-S-TMSI split into part 1 and part 2",
                "TS 38.331 §5.3.3.3, §5.3.3.4")
def test_rrc_setup_uses_5g_s_tmsi(ss):
    with ss.preamble():
        guti = ss.register(t3512={"unit": 3, "value": 5})  # T3512 = 10 s
        s_tmsi = (guti["amfSetId"] << 38) | (guti["amfPointer"] << 32) | guti["tmsi"]
    with ss.step(1, "Wait for T3512 so the registered UE sets up a new connection"):
        ss.advance(10_000)
    with ss.step(2, "Check: RRCSetupRequest carries ng-5G-S-TMSI-Part1 = the 39 LSBs of the 5G-S-TMSI"):
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest", **{
            "ue-Identity": {"ng-5G-S-TMSI-Part1": s_tmsi & MAX39}}), within_ms=1000)
    with ss.step(3, "The SS transmits RRCSetup"):
        ss.answer_setup(0)
    with ss.step(4, "Check: RRCSetupComplete carries ng-5G-S-TMSI-Part2 = the 9 MSBs"):
        ss.expect(channel="UL-DCCH", rrc=message("rrcSetupComplete", **{
            "ng-5G-S-TMSI-Value": {"ng-5G-S-TMSI-Part2": s_tmsi >> 39}}))


@pytest.mark.tc("VD-RRC-003", "RRC connection establishment / T300 expiry", "TS 38.331 §5.3.3.7, TS 24.501 §5.5.1.2.7")
def test_t300_expiry(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"))
    with ss.step(1, "The SS does not answer; T300 (1000 ms) expires"):
        ss.advance(1000)
    with ss.step(2, "Check: the UE is in RRC_IDLE and NAS counted one failed attempt"):
        st = ss.ue.state
        ss.check(st["rrc"] == "RRC_IDLE", f"UE in {st['rrc']}")
        ss.check(st["timers"]["T300"] is None, "T300 still running")
        ss.check(st["attempt_counter"] == 1, f"attempt counter {st['attempt_counter']}")
    with ss.step(3, "Check: no new RRCSetupRequest before T3511 (10 s) expires"):
        ss.expect_silence(9_900)
    with ss.step(4, "Check: the UE retries when T3511 expires"):
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"), within_ms=200)


@pytest.mark.tc("VD-RRC-004", "RRC connection reject / T302 barring and retry when barring is alleviated",
                "TS 38.331 §5.3.15, TS 24.501 §5.5.1.2.7 b)")
def test_rrc_reject_wait_time(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"))
    with ss.step(1, "The SS transmits RRCReject with waitTime 16 s"):
        ss.send_dl_ccch(rrc.rrc_reject(16))
        ss.advance(5)
    with ss.step(2, "Check: T302 is running with the signalled wait time"):
        t302 = ss.ue.timer("T302")
        ss.check(t302 is not None and 15_000 < t302 <= 16_000, f"T302 remaining {t302}")
    with ss.step(3, "Check: no access attempt while T302 runs"):
        ss.expect_silence(15_900)
    with ss.step(4, "Check: registration is re-attempted when barring is alleviated (T302 expiry)"):
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"), within_ms=600)


@pytest.mark.tc("VD-RRC-005", "Initial AS security activation / success", "TS 38.331 §5.3.4")
def test_as_security_activation(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
        ss.authenticate()
        ss.nas_security()
    with ss.step(1, "The SS transmits SecurityModeCommand (nea0, nia2), integrity protected"):
        complete = ss.as_security()
    with ss.step(2, "Check: SecurityModeComplete is integrity protected with K_RRCint"):
        ss.check(complete.integrity_ok is True, "MAC-I did not verify")
    with ss.step(3, "Check: subsequent uplink messages are integrity protected"):
        ss.send_nas(nas.registration_accept({"type": "5G-GUTI", "mcc": "001", "mnc": "01", "amfRegionId": 1,
                                             "amfSetId": 1, "amfPointer": 1, "tmsi": 7}))
        pdu = ss.expect_nas(message("RegistrationComplete"))
        ss.check(pdu.integrity_ok is True, "RegistrationComplete PDCP MAC-I did not verify")


@pytest.mark.tc("VD-RRC-006", "Initial AS security activation / SecurityModeCommand integrity failure",
                "TS 38.331 §5.3.4.3")
def test_as_security_mode_command_bad_mac(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
        ss.authenticate()
        ss.nas_security()
    with ss.step(1, "The SS transmits SecurityModeCommand with an invalid MAC-I"):
        txid = ss.next_txid()
        ss.send_dl_dcch(rrc.security_mode_command(txid), mac_override=b"\xde\xad\xbe\xef")
    with ss.step(2, "Check: SecurityModeFailure, sent without integrity protection (MAC-I all zero)"):
        pdu = ss.expect(channel="UL-DCCH", rrc=message("securityModeFailure", **{"rrc-TransactionIdentifier": txid}))
        ss.check(pdu.raw[-4:] == bytes(4), f"MAC-I is {pdu.raw[-4:].hex()}, expected 00000000")
    with ss.step(3, "Check: the UE stays in RRC_CONNECTED without AS security"):
        st = ss.ue.state
        ss.check(st["rrc"] == "RRC_CONNECTED" and not st["as_security"], f"UE state {st['rrc']}, AS security {st['as_security']}")


@pytest.mark.tc("VD-RRC-007", "RRC release / actions delayed by 60 ms", "TS 38.331 §5.3.8.3")
def test_rrc_release_delay(ss):
    with ss.preamble():
        ss.register(release=False)
    with ss.step(1, "The SS transmits RRCRelease"):
        ss.send_dl_dcch(rrc.rrc_release(ss.next_txid()))
    with ss.step(2, "Check: the UE is still in RRC_CONNECTED 50 ms later"):
        ss.advance(50)
        ss.check(ss.ue.state["rrc"] == "RRC_CONNECTED", "released before the 60 ms delay")
    with ss.step(3, "Check: the UE is in RRC_IDLE 70 ms after reception and sends nothing"):
        ss.advance(20)
        ss.check(ss.ue.state["rrc"] == "RRC_IDLE", f"UE in {ss.ue.state['rrc']}")
        ss.expect_silence(1000)


@pytest.mark.tc("VD-RRC-008", "RRC release with waitTime / access barred until T302 expiry",
                "TS 38.331 §5.3.8.3, TS 24.501 §5.5.2.2.6")
def test_rrc_release_wait_time_bars_deregistration(ss):
    with ss.preamble():
        ss.register(release=False)
    with ss.step(1, "The SS transmits RRCRelease with waitTime 5 s"):
        ss.send_dl_dcch(rrc.rrc_release(ss.next_txid(), wait_time=5))
        ss.advance(100)
    with ss.step(2, "The UE is made to de-register while T302 is running"):
        ss.check(ss.ue.timer("T302") is not None, "T302 not started by RRCRelease waitTime")
        ss.ue.deregister()
    with ss.step(3, "Check: no access attempt before T302 expires"):
        ss.expect_silence(4_800)
    with ss.step(4, "Check: de-registration starts as soon as barring is alleviated"):
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"), within_ms=600)


@pytest.mark.tc("VD-RRC-009", "RRC connection establishment / DL-CCCH abstract syntax error is ignored",
                "TS 38.331 §10.4")
def test_dl_ccch_syntax_error_ignored(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"))
    with ss.step(1, "The SS transmits an undecodable DL-CCCH message"):
        ss.send_dl_ccch(b"\x7f\xff\xff\xff", "garbage")
    with ss.step(2, "Check: the UE ignores it (no uplink, T300 still running)"):
        ss.expect_silence(200)
        ss.check(ss.ue.timer("T300") is not None, "T300 stopped by an undecodable message")
    with ss.step(3, "Check: a valid RRCSetup is still accepted"):
        ss.answer_setup(1)
        ss.expect(channel="UL-DCCH", rrc=message("rrcSetupComplete", **{"rrc-TransactionIdentifier": 1}))


@pytest.mark.tc("VD-RRC-010", "Unsolicited RRCSetup in RRC_IDLE is ignored", "TS 38.331 §5.3.3.4")
def test_unsolicited_rrc_setup_ignored(ss):
    with ss.preamble():
        ss.ue.power_on()
    with ss.step(1, "The SS transmits RRCSetup although the UE did not request a connection"):
        ss.send_dl_ccch(rrc.rrc_setup(0))
    with ss.step(2, "Check: no uplink and the UE stays in RRC_IDLE"):
        ss.expect_silence(500)
        ss.check(ss.ue.state["rrc"] == "RRC_IDLE", "UE left RRC_IDLE")


@pytest.mark.tc("VD-RRC-011", "Integrity failure on DL-DCCH after AS security / message not processed",
                "TS 38.331 §5.3.4, TS 33.501 §6.5")
def test_dl_dcch_integrity_failure(ss):
    with ss.preamble():
        ss.register(release=False)
    with ss.step(1, "The SS transmits a protected IDENTITY REQUEST in a PDCP PDU with an invalid MAC-I"):
        nas_pdu = ss.nas_ctx.protect(nas.encode(nas.plain("IdentityRequest", identityType=1)), 2, 1)
        ss.send_dl_dcch(rrc.dl_information_transfer(ss.next_txid(), nas_pdu),
                        "dlInformationTransfer [IdentityRequest*] (MAC-I corrupted)", mac_override=b"\x00\x11\x22\x33")
    with ss.step(2, "Check: the UE does not answer the corrupted message"):
        ss.expect_silence(1_000)


@pytest.mark.tc("VD-RRC-012", "Duplicated DL-DCCH PDU is delivered only once", "TS 38.323 §5.2.2.1")
def test_duplicate_pdcp_pdu_discarded(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.connect()
    with ss.step(1, "The SS transmits IDENTITY REQUEST (SUCI) twice in the same PDCP PDU"):
        pdu = ss.pdcp.wrap(rrc.encode("DL-DCCH", rrc.dl_information_transfer(ss.next_txid(), nas.encode(
            nas.plain("IdentityRequest", identityType=1)))))
        ss.send_dl_pdcp_raw(pdu, "dlInformationTransfer [IdentityRequest]")
        ss.send_dl_pdcp_raw(pdu, "dlInformationTransfer [IdentityRequest] (duplicate)")
    with ss.step(2, "Check: exactly one IDENTITY RESPONSE"):
        ss.expect_nas(message("IdentityResponse", mobileIdentity={"type": "SUCI"}))
        ss.expect_silence(500)


@pytest.mark.tc("VD-RRC-013", "RRCSetup without SRB1 / UE does not use DCCH", "TS 38.331 §5.3.3.4")
def test_rrc_setup_without_srb1(ss):
    with ss.preamble():
        ss.ue.power_on()
        ss.ue.register()
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"))
    with ss.step(1, "The SS transmits RRCSetup whose RadioBearerConfig has no SRB1"):
        ss.answer_setup(0, srbs=())
    with ss.step(2, "Check: no RRCSetupComplete and the UE stays in RRC_IDLE"):
        ss.expect_silence(500)
        ss.check(ss.ue.state["rrc"] == "RRC_IDLE", "UE entered RRC_CONNECTED without SRB1")
