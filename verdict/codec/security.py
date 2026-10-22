"""Security functions for the test system: MILENAGE, 5G key derivation, 128-NIA2/NEA2, NAS and
PDCP protection.

Built on the ``cryptography`` package's AES and CMAC primitives, so it shares no code with
NR-Lite's own from-scratch implementation; the cross-check tests in tests/unit compare the two.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

UPLINK, DOWNLINK = 0, 1


class IntegrityError(Exception):
    pass


def aes(key: bytes, block: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _rot(x: bytes, bits: int) -> bytes:
    n = bits // 8
    return x[n:] + x[:n]


# ---- MILENAGE (TS 35.206) ---------------------------------------------------------------------


def opc_from_op(k: bytes, op: bytes) -> bytes:
    return _xor(aes(k, op), op)


def milenage(k: bytes, opc: bytes, rand: bytes, sqn: bytes = b"\x00" * 6, amf: bytes = b"\x80\x00") -> dict:
    temp = aes(k, _xor(rand, opc))
    in1 = sqn + amf + sqn + amf
    out1 = _xor(aes(k, _xor(temp, _rot(_xor(in1, opc), 64))), opc)

    def out(r: int, c: int) -> bytes:
        x = bytearray(_rot(_xor(temp, opc), r))
        x[15] ^= c
        return _xor(aes(k, bytes(x)), opc)

    out2, out3, out4, out5 = out(0, 1), out(32, 2), out(64, 4), out(96, 8)
    return {"mac_a": out1[:8], "mac_s": out1[8:], "res": out2[8:], "ak": out2[:6], "ck": out3, "ik": out4,
            "ak_star": out5[:6]}


# ---- KDF and the 5G key hierarchy (TS 33.220 Annex B, TS 33.501 Annex A) ---------------------------


def kdf(key: bytes, fc: int, *params: bytes) -> bytes:
    s = bytes([fc]) + b"".join(p + len(p).to_bytes(2, "big") for p in params)
    return hmac.new(key, s, hashlib.sha256).digest()


def serving_network_name(mcc: str = "001", mnc: str = "01") -> str:
    return f"5G:mnc{mnc.zfill(3)}.mcc{mcc}.3gppnetwork.org"


@dataclass
class AuthVector:
    rand: bytes
    autn: bytes
    xres_star: bytes
    hxres_star: bytes
    kausf: bytes
    kseaf: bytes
    sqn: int


def generate_av(k: bytes, opc: bytes, sqn: int, rand: bytes, snn: str, amf: bytes = b"\x80\x00") -> AuthVector:
    sqn_b = sqn.to_bytes(6, "big")
    m = milenage(k, opc, rand, sqn_b, amf)
    sqn_xor_ak = _xor(sqn_b, m["ak"])
    autn = sqn_xor_ak + amf + m["mac_a"]
    ckik = m["ck"] + m["ik"]
    xres_star = kdf(ckik, 0x6B, snn.encode(), rand, m["res"])[16:]
    hxres_star = hashlib.sha256(rand + xres_star).digest()[16:]
    kausf = kdf(ckik, 0x6A, snn.encode(), sqn_xor_ak)
    kseaf = kdf(kausf, 0x6C, snn.encode())
    return AuthVector(rand, autn, xres_star, hxres_star, kausf, kseaf, sqn)


def verify_auts(k: bytes, opc: bytes, rand: bytes, auts: bytes) -> int | None:
    m = milenage(k, opc, rand)
    sqn_ms = _xor(auts[:6], m["ak_star"])
    if milenage(k, opc, rand, sqn_ms, b"\x00\x00")["mac_s"] != auts[6:]:
        return None
    return int.from_bytes(sqn_ms, "big")


def derive_kamf(kseaf: bytes, supi: str, abba: bytes = b"\x00\x00") -> bytes:
    return kdf(kseaf, 0x6D, supi.encode(), abba)


def algorithm_key(parent: bytes, distinguisher: int, alg: int) -> bytes:
    return kdf(parent, 0x69, bytes([distinguisher]), bytes([alg]))[16:]


NAS_ENC, NAS_INT, RRC_ENC, RRC_INT = 0x01, 0x02, 0x03, 0x04


def derive_kgnb(kamf: bytes, ul_nas_count: int) -> bytes:
    return kdf(kamf, 0x6E, ul_nas_count.to_bytes(4, "big"), b"\x01")


# ---- 128-NIA2 / 128-NEA2 ------------------------------------------------------------------------


def nia2(key: bytes, count: int, bearer: int, direction: int, message: bytes) -> bytes:
    c = cmac.CMAC(algorithms.AES(key))
    c.update(count.to_bytes(4, "big") + bytes([(bearer << 3) | (direction << 2), 0, 0, 0]) + message)
    return c.finalize()[:4]


def nea2(key: bytes, count: int, bearer: int, direction: int, data: bytes) -> bytes:
    iv = count.to_bytes(4, "big") + bytes([(bearer << 3) | (direction << 2)]) + bytes(11)
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return enc.update(data) + enc.finalize()


# ---- NAS security (TS 24.501 §4.4) ----------------------------------------------------------------

PLAIN, INT, INT_CIPH, INT_NEW, INT_CIPH_NEW = 0, 1, 2, 3, 4


@dataclass
class NasContext:
    kamf: bytes
    ea: int = 0
    ia: int = 2
    ngksi: int = 0
    ul_count: int = 0  # next expected / used
    dl_count: int = 0
    knas_int: bytes = field(init=False)
    knas_enc: bytes = field(init=False)

    def __post_init__(self) -> None:
        self.knas_int = algorithm_key(self.kamf, NAS_INT, self.ia)
        self.knas_enc = algorithm_key(self.kamf, NAS_ENC, self.ea)

    def _mac(self, count: int, direction: int, sqn: int, payload: bytes) -> bytes:
        if self.ia == 0:
            return bytes(4)
        return nia2(self.knas_int, count, 0, direction, bytes([sqn]) + payload)

    def _cipher(self, count: int, direction: int, data: bytes) -> bytes:
        if self.ea == 0 or not data:
            return data
        return nea2(self.knas_enc, count, 0, direction, data)

    def protect(self, plain: bytes, sht: int = INT_CIPH, direction: int = DOWNLINK, count: int | None = None) -> bytes:
        if count is None:
            count = self.dl_count if direction == DOWNLINK else self.ul_count
            if direction == DOWNLINK:
                self.dl_count += 1
            else:
                self.ul_count += 1
        sqn = count & 0xFF
        payload = self._cipher(count, direction, plain) if sht in (INT_CIPH, INT_CIPH_NEW) else plain
        return bytes([0x7E, sht]) + self._mac(count, direction, sqn, payload) + bytes([sqn]) + payload

    @staticmethod
    def estimate(expected: int, sqn: int) -> int:
        overflow = (expected >> 8) & 0xFFFF
        if sqn < (expected & 0xFF):
            overflow = (overflow + 1) & 0xFFFF
        return (overflow << 8) | sqn

    def unprotect(self, pdu: bytes, direction: int = UPLINK) -> tuple[bytes, int]:
        if len(pdu) < 7:
            raise IntegrityError("protected NAS message too short")
        sht, mac, sqn, payload = pdu[1] & 0xF, pdu[2:6], pdu[6], pdu[7:]
        expected = self.ul_count if direction == UPLINK else self.dl_count
        count = self.estimate(expected, sqn)
        if self._mac(count, direction, sqn, payload) != mac:
            raise IntegrityError(f"NAS MAC mismatch (COUNT {count})")
        if direction == UPLINK:
            self.ul_count = count + 1
        else:
            self.dl_count = count + 1
        plain = self._cipher(count, direction, payload) if sht in (INT_CIPH, INT_CIPH_NEW) else payload
        return plain, count


# ---- PDCP for SRBs (TS 38.323) ------------------------------------------------------------------


@dataclass
class PdcpSrb:
    srb_id: int = 1
    tx_direction: int = DOWNLINK
    tx_next: int = 0
    rx_deliv: int = 0
    tx_int: bytes | None = None
    rx_int: bytes | None = None
    tx_enc: bytes | None = None
    rx_enc: bytes | None = None

    @property
    def bearer(self) -> int:
        return self.srb_id - 1

    def wrap(self, sdu: bytes, *, mac_override: bytes | None = None) -> bytes:
        count = self.tx_next
        self.tx_next += 1
        sn = count % 4096
        header = bytes([(sn >> 8) & 0x0F, sn & 0xFF])
        mac = bytes(4)
        if self.tx_int is not None:
            mac = nia2(self.tx_int, count, self.bearer, self.tx_direction, header + sdu)
        if mac_override is not None:
            mac = mac_override
        body = sdu + mac
        if self.tx_enc is not None:
            body = nea2(self.tx_enc, count, self.bearer, self.tx_direction, body)
        return header + body

    def unwrap(self, pdu: bytes, *, verify_with: bytes | None = None) -> tuple[bytes, int, bool | None]:
        """Returns (sdu, count, integrity_ok). integrity_ok is None when no key is available."""
        if len(pdu) < 6:
            raise IntegrityError("PDCP PDU too short")
        rx_dir = 1 - self.tx_direction
        sn = ((pdu[0] & 0x0F) << 8) | pdu[1]
        deliv_sn, hfn = self.rx_deliv % 4096, self.rx_deliv // 4096
        if sn < deliv_sn - 2048:
            hfn += 1
        elif sn >= deliv_sn + 2048 and hfn > 0:
            hfn -= 1
        count = hfn * 4096 + sn
        body = pdu[2:]
        if self.rx_enc is not None:
            body = nea2(self.rx_enc, count, self.bearer, rx_dir, body)
        sdu, mac = body[:-4], body[-4:]
        key = verify_with if verify_with is not None else self.rx_int
        ok = None
        if key is not None:
            ok = nia2(key, count, self.bearer, rx_dir, pdu[:2] + sdu) == mac
        if ok is not False:
            self.rx_deliv = max(self.rx_deliv, count + 1)
        return sdu, count, ok
