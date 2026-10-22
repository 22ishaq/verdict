"""Verdict's security functions: published test vectors and random cross-checks against NR-Lite."""

import os
import random

import pytest

from verdict import _nrlite
from verdict.codec import security as sec

MILENAGE = [  # TS 35.207 test sets 1-3: K, RAND, SQN, AMF, OP, OPc, f1, f1*, f2, f5, f3, f4, f5*
    ("465b5ce8b199b49faa5f0a2ee238a6bc", "23553cbe9637a89d218ae64dae47bf35", "ff9bb4d0b607", "b9b9",
     "cdc202d5123e20f62b6d676ac72cb318", "cd63cb71954a9f4e48a5994e37a02baf", "4a9ffac354dfafb3", "01cfaf9ec4e871e9",
     "a54211d5e3ba50bf", "aa689c648370", "b40ba9a3c58b2a05bbf0d987b21bf8cb", "f769bcd751044604127672711c6d3441",
     "451e8beca43b"),
    ("0396eb317b6d1c36f19c1c84cd6ffd16", "c00d603103dcee52c4478119494202e8", "fd8eef40df7d", "af17",
     "ff53bade17df5d4e793073ce9d7579fa", "53c15671c60a4b731c55b4a441c0bde2", "5df5b31807e258b0", "a8c016e51ef4a343",
     "d3a628ed988620f0", "c47783995f72", "58c433ff7a7082acd424220f2b67c556", "21a8c1f929702adb3e738488b9f5c5da",
     "30f1197061c1"),
    ("fec86ba6eb707ed08905757b1bb44b8f", "9f7c8d021accf4db213ccff0c7f71a6a", "9d0277595ffc", "725c",
     "dbc59adcb6f9a0ef735477b7fadf8374", "1006020f0a478bf6b699f15c062e42b3", "9cabc3e99baf7281", "95814ba2b3044324",
     "8011c48c0c214ed2", "33484dc2136b", "5dbdbb2954e8f3cde665b046179a5098", "59a92d3b476a0443487055cf88b2307b",
     "deacdd848cc6"),
]


@pytest.mark.parametrize("v", MILENAGE, ids=["set1", "set2", "set3"])
def test_milenage_ts35207(v):
    k, rand, sqn, amf, op, opc, f1, f1s, f2, f5, f3, f4, f5s = (bytes.fromhex(x) for x in v)
    assert sec.opc_from_op(k, op) == opc
    m = sec.milenage(k, opc, rand, sqn, amf)
    assert (m["mac_a"], m["mac_s"], m["res"], m["ak"], m["ck"], m["ik"], m["ak_star"]) == (f1, f1s, f2, f5, f3, f4, f5s)


def test_nia2_eia2_test_set_2():
    mac = sec.nia2(bytes.fromhex("d3c5d592327fb11c4035c6680af8c6d1"), 0x398A59B4, 0x1A, 1, bytes.fromhex("484583d5afe082ae"))
    assert mac.hex() == "b93787e6"


def test_nea2_eea2_test_set_1():
    pt = bytes.fromhex("981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc66b1f0")
    ct = sec.nea2(bytes.fromhex("d3c5d592327fb11c4035c6680af8c6d1"), 0x398A59B4, 0x15, 1, pt)
    expected = bytes.fromhex("e9fed8a63d155304d71df20bf3e82214b20ed7dad2f233dc3c22d7bdeeed8e78")
    assert ct[:31] == expected[:31]
    assert ct[31] & 0xF8 == expected[31]  # the test data is 253 bits long


def test_random_cross_check_with_nrlite():
    rng = random.Random(7)
    for _ in range(100):
        key, data = os.urandom(16), os.urandom(rng.randrange(0, 200))
        count, bearer, direction = rng.getrandbits(32), rng.randrange(32), rng.randrange(2)
        assert sec.nia2(key, count, bearer, direction, data) == _nrlite.nia2(key, count, bearer, direction, data)
        assert sec.nea2(key, count, bearer, direction, data) == _nrlite.nea2(key, count, bearer, direction, data)
        params = [os.urandom(rng.randrange(0, 40)) for _ in range(rng.randrange(1, 4))]
        assert sec.kdf(key * 2, 0x69, *params) == _nrlite.kdf(key * 2, 0x69, params)
        k, opc, rand = os.urandom(16), os.urandom(16), os.urandom(16)
        theirs = _nrlite.milenage(k, opc, rand, bytes(6), b"\x80\x00")
        ours = sec.milenage(k, opc, rand)
        assert all(ours[f] == theirs[f] for f in theirs)


def test_auth_vector_resync_round_trip():
    k, opc, rand = os.urandom(16), os.urandom(16), os.urandom(16)
    m = sec.milenage(k, opc, rand)
    sqn_ms = (123456).to_bytes(6, "big")
    auts = bytes(a ^ b for a, b in zip(sqn_ms, m["ak_star"])) + sec.milenage(k, opc, rand, sqn_ms, b"\0\0")["mac_s"]
    assert sec.verify_auts(k, opc, rand, auts) == 123456
    assert sec.verify_auts(k, opc, rand, auts[:-1] + b"\x00") is None


def test_nas_context_protect_unprotect_and_replay():
    ctx_a, ctx_b = sec.NasContext(os.urandom(32), 2, 2), None
    ctx_b = sec.NasContext(ctx_a.kamf, 2, 2)
    pdu = ctx_a.protect(b"\x7e\x00\x43", sec.INT_CIPH, sec.UPLINK)
    assert ctx_b.unprotect(pdu, sec.UPLINK) == (b"\x7e\x00\x43", 0)
    with pytest.raises(sec.IntegrityError):
        ctx_b.unprotect(pdu, sec.UPLINK)


def test_pdcp_wrap_unwrap_with_integrity_and_ciphering():
    tx, rx = sec.PdcpSrb(1, sec.UPLINK), sec.PdcpSrb(1, sec.DOWNLINK)
    key_i, key_c = os.urandom(16), os.urandom(16)
    tx.tx_int, tx.tx_enc, rx.rx_int, rx.rx_enc = key_i, key_c, key_i, key_c
    for i in range(5):
        sdu, count, ok = rx.unwrap(tx.wrap(b"hello" + bytes([i])))
        assert (sdu, count, ok) == (b"hello" + bytes([i]), i, True)
