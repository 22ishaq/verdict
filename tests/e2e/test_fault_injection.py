"""End-to-end test cases: full NR-Lite stack with faults injected on the air interface."""

import pytest


@pytest.mark.tc("VD-E2E-001", "Lost RRCSetup / recovery through T300 and T3511", "TS 38.331 §5.3.3.7, TS 24.501 §5.5.1.2.7")
def test_lost_rrc_setup(testbed_factory):
    tb = testbed_factory()
    tb.drop_first("rrcSetup", direction="DL")
    tb.register_all()
    tb.advance(12_000)
    assert tb.registered(), tb.ue()
    assert tb.injections, "nothing was dropped"


@pytest.mark.tc("VD-E2E-002", "Lost REGISTRATION COMPLETE / T3550 retransmission", "TS 24.501 §5.5.1.2.8")
def test_lost_registration_complete(testbed_factory):
    tb = testbed_factory(amf={"release_after_registration": False})
    tb.drop_first("RegistrationComplete", direction="UL")
    tb.register_all()
    tb.advance(7_000)
    assert tb.registered()
    assert tb.sim.amf_counters()["retransmissions"] == 1


@pytest.mark.tc("VD-E2E-003", "Lost AUTHENTICATION RESPONSE / T3560 and SQN re-synchronisation", "TS 24.501 §5.4.1.3.7")
def test_lost_authentication_response(testbed_factory):
    tb = testbed_factory()
    tb.drop_first("AuthenticationResponse", direction="UL")
    tb.register_all()
    tb.advance(8_000)
    assert tb.registered()
    assert tb.sim.amf_counters()["resyncs"] == 1


@pytest.mark.tc("VD-E2E-004", "Corrupted NAS SECURITY MODE COMMAND / reject, abort, retry", "TS 24.501 §5.4.2.5")
def test_corrupted_nas_smc(testbed_factory):
    tb = testbed_factory()

    def flip_mac(pdcp: bytes) -> bytes:
        b = bytearray(pdcp)
        b[-12] ^= 0x01  # a byte inside the NAS PDU (before the 4-octet PDCP MAC-I)
        return bytes(b)

    tb.corrupt_first("SecurityModeCommand", flip_mac, direction="DL")
    tb.register_all()
    tb.advance(13_000)
    assert tb.registered()


@pytest.mark.tc("VD-E2E-005", "Corrupted RRC SecurityModeCommand / failure, abort, retry", "TS 38.331 §5.3.4.3")
def test_corrupted_rrc_smc(testbed_factory):
    tb = testbed_factory()
    tb.corrupt_first("securityModeCommand", lambda b: b[:-1] + bytes([b[-1] ^ 0xFF]), direction="DL")
    tb.register_all()
    tb.advance(13_000)
    assert tb.registered()
    assert tb.ue()["counters"]["rrc_security_mode_failures"] == 1


@pytest.mark.tc("VD-E2E-006", "Reordered downlink / AS SMC delayed behind later traffic", "TS 38.323 §5.2.2")
def test_reordered_downlink(testbed_factory):
    tb = testbed_factory()
    tb.delay_first("securityModeCommand", 40, direction="DL")
    tb.register_all()
    tb.advance(2_000)
    assert tb.registered()


@pytest.mark.tc("VD-E2E-007", "Duplicated downlink PDCP PDU is discarded", "TS 38.323 §5.2.2.1")
def test_duplicated_downlink(testbed_factory):
    tb = testbed_factory()
    tb.duplicate_first("AuthenticationRequest", direction="DL")
    tb.register_all()
    tb.advance(2_000)
    assert tb.registered()
    assert tb.sim.amf_counters()["authentications"] == 1


@pytest.mark.tc("VD-E2E-008", "Ten UEs register concurrently", "TS 24.501 §5.5.1.2")
def test_ten_ues(testbed_factory):
    tb = testbed_factory(n_ues=10)
    tb.register_all()
    tb.advance(3_000)
    assert all(tb.registered(i) for i in range(10))
    tmsis = {tb.ue(i)["guti"]["tmsi"] for i in range(10)}
    assert len(tmsis) == 10


@pytest.mark.tc("VD-E2E-009", "Same seed reproduces the same trace bit for bit", "determinism")
def test_determinism(testbed_factory):
    def run(seed):
        tb = testbed_factory(seed=seed, n_ues=2)
        tb.register_all()
        tb.advance(2_000)
        return [r["raw"] for r in tb.sim.trace()]

    assert run(7) == run(7)
    assert run(7) != run(8)
