"""Network-side test cases: Verdict plays the UE towards NR-Lite's gNB and AMF."""

import pytest

from verdict.codec import nas, rrc
from verdict.codec import security as sec
from verdict.templates import ANY, OneOf, message


@pytest.mark.tc("VD-NW-001", "Registration of an independent UE implementation", "TS 24.501 §5.5.1.2, TS 38.331 §5.3")
def test_registration_with_emulated_ue(ue_emulator):
    ue_emulator.register()
    view = ue_emulator.sim.amf_ue("001010000000001")
    assert view["state"] == "5GMM-REGISTERED", view


@pytest.mark.tc("VD-NW-002", "gNB ignores a truncated RRCSetupRequest", "TS 38.331 §10.4")
def test_gnb_ignores_truncated_setup_request(ue_emulator):
    ue_emulator.send_ccch(b"\x12\x46\x8a")
    ue_emulator.expect_silence(500)
    assert ue_emulator.sim.gnb_counters()["ue_count"] == 0


@pytest.mark.tc("VD-NW-003", "gNB accepts RRCSetupRequest with the spare bit set", "TS 38.331 §6.2.2 (spare bits)")
def test_gnb_ignores_spare_bit(ue_emulator):
    data = bytearray(rrc.encode("UL-CCCH", {"message": "rrcSetupRequest", "body": {
        "ue-Identity": {"randomValue": 7}, "establishmentCause": "mo-Signalling"}}))
    data[-1] |= 0x01  # spare
    ue_emulator.send_ccch(bytes(data))
    ue_emulator.expect({"message": "rrcSetup"})


@pytest.mark.tc("VD-NW-004", "gNB ignores RRCSetupComplete with a wrong transaction identifier", "TS 38.331 §5.3.3")
def test_gnb_wrong_transaction_id(ue_emulator):
    ue_emulator.send_ccch({"message": "rrcSetupRequest", "body": {"ue-Identity": {"randomValue": 1},
                                                                  "establishmentCause": "mo-Signalling"}})
    setup = ue_emulator.expect({"message": "rrcSetup"})
    wrong = (setup.rrc["body"]["rrc-TransactionIdentifier"] + 1) % 4
    ue_emulator.send_dcch({"message": "rrcSetupComplete", "body": {
        "rrc-TransactionIdentifier": wrong, "selectedPLMN-Identity": 1,
        "dedicatedNAS-Message": nas.encode(ue_emulator.registration_request()).hex()}})
    ue_emulator.expect_silence(500)
    assert ue_emulator.sim.amf_counters()["authentications"] == 0


@pytest.mark.tc("VD-NW-005", "gNB survives undecodable UL-DCCH and keeps serving the UE", "TS 38.331 §10.4")
def test_gnb_survives_garbage_dcch(ue_emulator):
    ue_emulator.connect(nas.encode(ue_emulator.registration_request()))
    auth = ue_emulator.expect(nas_template={"message": "AuthenticationRequest"})
    ue_emulator.send_dcch(b"\xff\xff\xff\xff\xff")
    ue_emulator.send_dcch(b"")
    ue_emulator.settle()
    assert ue_emulator.sim.gnb_counters()["decode_errors"] == 2
    # The connection is still usable: the registration continues.
    ue_emulator.send_nas(ue_emulator.answer_authentication(auth.nas))
    ue_emulator.expect(nas_template={"message": "SecurityModeCommand"})


@pytest.mark.tc("VD-NW-006", "AMF rejects a wrong RES*", "TS 33.501 §6.1.3.2.2")
def test_amf_wrong_res_star(ue_emulator):
    ue_emulator.connect(nas.encode(ue_emulator.registration_request()))
    ue_emulator.expect(nas_template={"message": "AuthenticationRequest"})
    ue_emulator.send_nas(nas.encode({"message": "AuthenticationResponse", "body": {"resStar": "00" * 16}}))
    ue_emulator.expect(nas_template={"message": "AuthenticationReject"})


@pytest.mark.tc("VD-NW-007", "AMF re-synchronises on AUTS", "TS 33.102 §6.3.5")
def test_amf_resync(ue_emulator):
    ue_emulator.connect(nas.encode(ue_emulator.registration_request()))
    req = ue_emulator.expect(nas_template={"message": "AuthenticationRequest"}).nas
    rand = bytes.fromhex(req["body"]["rand"])
    sqn_ms = 500
    m = sec.milenage(sec_k(), sec_opc(), rand)
    mac_s = sec.milenage(sec_k(), sec_opc(), rand, sqn_ms.to_bytes(6, "big"), b"\x00\x00")["mac_s"]
    auts = bytes(a ^ b for a, b in zip(sqn_ms.to_bytes(6, "big"), m["ak_star"])) + mac_s
    ue_emulator.send_nas(nas.encode({"message": "AuthenticationFailure", "body": {"5gmmCause": 21, "auts": auts.hex()}}))
    again = ue_emulator.expect(nas_template={"message": "AuthenticationRequest"}).nas
    autn = bytes.fromhex(again["body"]["autn"])
    ak = sec.milenage(sec_k(), sec_opc(), bytes.fromhex(again["body"]["rand"]))["ak"]
    sqn = int.from_bytes(bytes(a ^ b for a, b in zip(autn[:6], ak)), "big")
    assert sqn == sqn_ms + 1, f"new challenge uses SQN {sqn}, expected {sqn_ms + 1}"


@pytest.mark.tc("VD-NW-008", "AMF discards an unprotected REGISTRATION COMPLETE after security activation", "TS 24.501 §4.4.4.3")
def test_amf_discards_plain_after_security(ue_emulator):
    ue_emulator.connect(nas.encode(ue_emulator.registration_request()))
    auth = ue_emulator.expect(nas_template={"message": "AuthenticationRequest"})
    ue_emulator.send_nas(ue_emulator.answer_authentication(auth.nas))
    smc = ue_emulator.expect(nas_template={"message": "SecurityModeCommand"})
    ue_emulator.send_nas(ue_emulator.answer_security_mode(smc))
    ue_emulator.expect({"message": "securityModeCommand"})
    ue_emulator.send_nas(nas.encode({"message": "RegistrationComplete", "body": {}}))
    ue_emulator.settle(100)
    assert ue_emulator.sim.amf_counters()["discarded_plain"] == 1
    assert ue_emulator.sim.amf_ue("001010000000001")["state"] != "5GMM-REGISTERED"


@pytest.mark.tc("VD-NW-009", "AMF discards a replayed SECURITY MODE COMPLETE", "TS 33.501 §6.4.3")
def test_amf_discards_replay(ue_emulator):
    ue_emulator.register()
    before = ue_emulator.sim.amf_counters()["integrity_failures"]
    replay = ue_emulator.nas_ctx.protect(nas.encode({"message": "RegistrationComplete", "body": {}}), sec.INT_CIPH,
                                         sec.UPLINK, count=0)
    ue_emulator.send_nas(replay)
    ue_emulator.settle()
    assert ue_emulator.sim.amf_counters()["integrity_failures"] == before + 1


@pytest.mark.tc("VD-NW-010", "AMF does not register a UE that omits its security capabilities", "TS 24.501 §5.5.1.2.2")
def test_amf_requires_security_capability(ue_emulator):
    ue_emulator.connect(nas.encode(ue_emulator.registration_request(with_caps=False)))
    reply = ue_emulator.expect(nas_template={"message": OneOf("RegistrationReject", "5GMMStatus")})
    assert reply.nas["message"] in ("RegistrationReject", "5GMMStatus")


@pytest.mark.tc("VD-NW-011", "gNB admission control / RRCReject with waitTime", "TS 38.331 §5.3.15")
def test_gnb_admission_control(ue_emulator):
    ue_emulator.sim.configure_gnb(max_ues=0, reject_wait_time_s=7)
    ue_emulator.send_ccch({"message": "rrcSetupRequest", "body": {"ue-Identity": {"randomValue": 1},
                                                                  "establishmentCause": "mo-Signalling"}})
    ue_emulator.expect({"message": "rrcReject", "body": {"waitTime": 7}})


def sec_k() -> bytes:
    from verdict.ss import TEST_K
    return TEST_K


def sec_opc() -> bytes:
    from verdict.ss import TEST_OPC
    return TEST_OPC
