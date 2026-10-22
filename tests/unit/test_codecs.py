"""Verdict's own RRC/NAS codecs: golden encodings, round trips, and cross-checks against NR-Lite.

The cross-checks are the point of having two implementations: random messages encoded by Verdict
must decode to the same structure in NR-Lite's C++ decoder (and vice versa via live traces).
"""

import json
import random

import pytest

from verdict import _nrlite
from verdict.codec import nas, per, rrc

# Golden encodings; each was decoded field by field with Wireshark's nr-rrc dissector.
GOLDEN_RRC = [
    ("UL-CCCH", {"message": "rrcSetupRequest", "body": {"ue-Identity": {"randomValue": 0x123456789A},
                                                        "establishmentCause": "mo-Signalling"}}, "12468acf1346"),
    ("DL-CCCH", rrc.rrc_setup(0), "2040002200040000"),
    ("DL-CCCH", rrc.rrc_reject(5), "0880"),
    ("DL-DCCH", rrc.security_mode_command(1, "nea0", "nia2"), "220810"),
    ("UL-DCCH", {"message": "securityModeComplete", "body": {"rrc-TransactionIdentifier": 1}}, "2a00"),
    ("UL-DCCH", {"message": "securityModeFailure", "body": {"rrc-TransactionIdentifier": 1}}, "3200"),
    ("DL-DCCH", {"message": "rrcRelease", "body": {"rrc-TransactionIdentifier": 3, "deprioritisationReq": {
        "deprioritisationType": "nr", "deprioritisationTimer": "min10"}, "waitTime": 7}}, "1616cc"),
    ("DL-DCCH", rrc.rrc_release(0), "1000"),
]


@pytest.mark.parametrize("channel,msg,hexstr", GOLDEN_RRC, ids=[g[1]["message"] for g in GOLDEN_RRC])
def test_rrc_golden_encoding(channel, msg, hexstr):
    assert rrc.encode(channel, msg).hex() == hexstr
    assert rrc.decode(channel, bytes.fromhex(hexstr)).message == msg


def _random_rrc(rng: random.Random) -> tuple[str, dict]:
    kind = rng.randrange(9)
    tx = rng.randrange(4)
    nas_hex = bytes(rng.getrandbits(8) for _ in range(rng.randrange(1, 300))).hex()
    if kind == 0:
        ident = rng.choice(["randomValue", "ng-5G-S-TMSI-Part1"])
        return "UL-CCCH", {"message": "rrcSetupRequest", "body": {"ue-Identity": {ident: rng.getrandbits(39)},
                                                                  "establishmentCause": rng.choice(rrc.CAUSES)}}
    if kind == 1:
        return "DL-CCCH", rrc.rrc_reject(rng.choice([None, rng.randint(1, 16)]))
    if kind == 2:
        return "DL-CCCH", rrc.rrc_setup(tx, srbs=tuple(rng.sample([1, 2, 3], rng.randint(1, 2))))
    if kind == 3:
        body = {"rrc-TransactionIdentifier": tx, "selectedPLMN-Identity": rng.randint(1, 12),
                "dedicatedNAS-Message": nas_hex}
        if rng.random() < 0.5:
            body["s-NSSAI-List"] = [rng.choice([{"sst": rng.randrange(256)},
                                                {"sst-SD": {"sst": rng.randrange(256), "sd": rng.getrandbits(24)}}])
                                    for _ in range(rng.randint(1, 8))]
        if rng.random() < 0.5:
            body["ng-5G-S-TMSI-Value"] = rng.choice([{"ng-5G-S-TMSI-Part2": rng.getrandbits(9)},
                                                     {"ng-5G-S-TMSI": rng.getrandbits(48)}])
        return "UL-DCCH", {"message": "rrcSetupComplete", "body": body}
    if kind == 4:
        return "UL-DCCH", {"message": "ulInformationTransfer", "body": {"dedicatedNAS-Message": nas_hex}}
    if kind == 5:
        return "DL-DCCH", rrc.dl_information_transfer(tx, bytes.fromhex(nas_hex))
    if kind == 6:
        return "DL-DCCH", rrc.security_mode_command(tx, rng.choice(rrc.CIPHERING), rng.choice([None, *rrc.INTEGRITY]))
    if kind == 7:
        return "DL-DCCH", rrc.rrc_release(tx, rng.choice([None, rng.randint(1, 16)]))
    return "UL-DCCH", {"message": rng.choice(["securityModeComplete", "securityModeFailure"]),
                       "body": {"rrc-TransactionIdentifier": tx}}


def test_rrc_cross_check_with_nrlite():
    rng = random.Random(2026)
    for _ in range(600):
        channel, msg = _random_rrc(rng)
        data = rrc.encode(channel, msg)
        ours = rrc.decode(channel, data).message
        theirs = json.loads(_nrlite.decode_rrc(channel, data))
        assert ours == theirs, (channel, data.hex())
        assert ours == msg


def test_rrc_decode_reports_trailing_and_truncated_data():
    good = rrc.encode("UL-CCCH", GOLDEN_RRC[0][1])
    with pytest.raises(per.PerDecodeError, match="trailing"):
        rrc.decode("UL-CCCH", good + b"\x00")
    for n in range(len(good)):
        with pytest.raises(ValueError):
            rrc.decode("UL-CCCH", good[:n])


def test_rrc_decode_records_field_spans():
    d = rrc.decode("UL-CCCH", bytes.fromhex("12468acf1346"))
    assert d.spans["body.establishmentCause"] == (43, 47)
    assert d.spans["body.ue-Identity"] == (3, 43)


def test_rrc_unsupported_alternative_is_named():
    with pytest.raises(rrc.Unsupported, match="rrcReconfiguration"):
        rrc.decode("DL-DCCH", bytes.fromhex("0000"))


SUCI = {"type": "SUCI", "mcc": "001", "mnc": "01", "routingIndicator": "0000", "protectionSchemeId": 0,
        "homeNetworkPublicKeyId": 0, "msin": "0000000001"}
GUTI = {"type": "5G-GUTI", "mcc": "001", "mnc": "01", "amfRegionId": 1, "amfSetId": 1, "amfPointer": 1,
        "tmsi": 0xAAF708BA}

NAS_MESSAGES = [
    {"message": "RegistrationRequest", "body": {"5gsRegistrationType": {"for": 0, "value": 1}, "ngKSI": {"tsc": 0, "ksi": 7},
                                                "mobileIdentity": SUCI, "ueSecurityCapability": {"5G-EA": 160, "5G-IA": 32},
                                                "requestedNSSAI": [{"sst": 1}], "5gmmCapability": "00"}},
    nas.registration_accept(GUTI, t3512={"unit": 1, "value": 1}),
    nas.plain("RegistrationComplete"),
    nas.registration_reject(22, {"unit": 1, "value": 2}),
    {"message": "DeregistrationRequest(UE originating)", "body": {"switchOff": 1, "accessType": 1,
                                                                  "ngKSI": {"tsc": 0, "ksi": 2}, "mobileIdentity": GUTI}},
    nas.plain("DeregistrationAccept(UE originating)"),
    nas.authentication_request(3, bytes(range(16)), bytes(range(16, 32))),
    nas.plain("AuthenticationResponse", resStar="ab" * 16),
    nas.plain("AuthenticationReject"),
    nas.plain("AuthenticationFailure", **{"5gmmCause": 21, "auts": "cd" * 14}),
    nas.plain("IdentityRequest", identityType=3),
    nas.plain("IdentityResponse", mobileIdentity={"type": "IMEI", "digits": "490154203237518"}),
    nas.security_mode_command(2, 2, 1, {"5G-EA": 160, "5G-IA": 32}, imeisv_request=True, additional=2),
    nas.plain("SecurityModeComplete", imeisv={"type": "IMEISV", "digits": "3534900698733190"}),
    nas.plain("SecurityModeReject", **{"5gmmCause": 23}),
    nas.plain("5GMMStatus", **{"5gmmCause": 97}),
]


@pytest.mark.parametrize("msg", NAS_MESSAGES, ids=[m["message"] for m in NAS_MESSAGES])
def test_nas_round_trip_and_cross_check(msg):
    data = nas.encode(msg)
    assert nas.decode(data).message == msg
    assert json.loads(_nrlite.decode_nas(data)) == msg


def test_nas_golden_authentication_request():
    data = nas.encode(nas.authentication_request(0, bytes(16), bytes(16)))
    assert data[:7].hex() == "7e005600020000"   # header, ngKSI 0, ABBA LV (0000)
    assert data[7] == 0x21 and data[24] == 0x20   # RAND (TV) then AUTN (TLV)
    assert len(data) == 42


def test_nas_errors_carry_the_5gmm_cause():
    with pytest.raises(nas.NasDecodeError) as e:
        nas.decode(b"\x7e\x00\x99")
    assert e.value.cause == 97
    with pytest.raises(nas.NasDecodeError) as e:
        nas.decode(b"\x7e\x00\x56\x00")
    assert e.value.cause == 96


def test_nas_unknown_optional_ies_skipped():
    data = nas.encode(nas.plain("RegistrationComplete"), extra_ies=bytes.fromhex("1c03aabbcc7c0002dead91"))
    assert nas.decode(data).message == nas.plain("RegistrationComplete")


def test_nas_imei_identity_encoding():
    raw = nas.encode_identity({"type": "IMEI", "digits": "490154203237518"})
    assert raw[0] & 0x0F == 0x0B  # odd number of digits, type IMEI
    assert nas.decode_identity(raw)["digits"] == "490154203237518"
