"""5GMM message codec for the test system (TS 24.501 §8.2, §9.11), independent of NR-Lite.

Messages are dicts shaped like NR-Lite's ``nas::to_json`` output::

    {"message": "AuthenticationRequest", "body": {"ngKSI": {"tsc": 0, "ksi": 0}, "abba": "0000", ...}}

``encode`` accepts ``extra_ies`` (raw bytes appended after the defined IEs) so test cases can build
messages with unknown or malformed optional IEs. ``decode`` returns the message plus the byte span
of every IE, which the report uses to highlight the failing part of a message.
"""

from __future__ import annotations

from dataclasses import dataclass, field

EPD_5GMM = 0x7E

TYPES = {
    0x41: "RegistrationRequest",
    0x42: "RegistrationAccept",
    0x43: "RegistrationComplete",
    0x44: "RegistrationReject",
    0x45: "DeregistrationRequest(UE originating)",
    0x46: "DeregistrationAccept(UE originating)",
    0x56: "AuthenticationRequest",
    0x57: "AuthenticationResponse",
    0x58: "AuthenticationReject",
    0x59: "AuthenticationFailure",
    0x5B: "IdentityRequest",
    0x5C: "IdentityResponse",
    0x5D: "SecurityModeCommand",
    0x5E: "SecurityModeComplete",
    0x5F: "SecurityModeReject",
    0x64: "5GMMStatus",
}
CODES = {v: k for k, v in TYPES.items()}

CAUSE_NAMES = {
    3: "Illegal UE", 6: "Illegal ME", 7: "5GS services not allowed", 9: "UE identity cannot be derived",
    11: "PLMN not allowed", 20: "MAC failure", 21: "Synch failure", 22: "Congestion",
    23: "UE security capabilities mismatch", 24: "Security mode rejected, unspecified",
    26: "Non-5G authentication unacceptable", 71: "ngKSI already in use", 95: "Semantically incorrect message",
    96: "Invalid mandatory information", 97: "Message type non-existent or not implemented",
    98: "Message type not compatible with the protocol state", 100: "Conditional IE error",
    111: "Protocol error, unspecified",
}


class NasDecodeError(ValueError):
    def __init__(self, message: str, cause: int = 96):
        super().__init__(message)
        self.cause = cause


@dataclass
class Decoded:
    message: dict
    spans: dict[str, tuple[int, int]] = field(default_factory=dict)  # byte ranges

    @property
    def name(self) -> str:
        return self.message["message"]


# ---- BCD / PLMN / identities ----------------------------------------------------------------------


def bcd(digits: str) -> bytes:
    out = bytearray()
    for i in range(0, len(digits), 2):
        lo = int(digits[i])
        hi = int(digits[i + 1]) if i + 1 < len(digits) else 0xF
        out.append((hi << 4) | lo)
    return bytes(out)


def unbcd(data: bytes) -> str:
    s = ""
    for i, b in enumerate(data):
        lo, hi = b & 0xF, b >> 4
        if lo > 9:
            raise NasDecodeError("BCD digit out of range")
        s += str(lo)
        if hi == 0xF:
            if i != len(data) - 1:
                raise NasDecodeError("BCD filler before last octet")
            break
        if hi > 9:
            raise NasDecodeError("BCD digit out of range")
        s += str(hi)
    return s


def plmn_bytes(mcc: str, mnc: str) -> bytes:
    mnc3 = int(mnc[2]) if len(mnc) == 3 else 0xF
    return bytes([(int(mcc[1]) << 4) | int(mcc[0]), (mnc3 << 4) | int(mcc[2]), (int(mnc[1]) << 4) | int(mnc[0])])


def plmn_from(b: bytes) -> tuple[str, str]:
    d = [b[0] & 0xF, b[0] >> 4, b[1] & 0xF, b[2] & 0xF, b[2] >> 4, b[1] >> 4]
    if any(x > 9 for x in d[:5]):
        raise NasDecodeError("PLMN digit out of range")
    mcc = f"{d[0]}{d[1]}{d[2]}"
    mnc = f"{d[3]}{d[4]}" + ("" if d[5] == 0xF else str(d[5]))
    return mcc, mnc


def encode_identity(ident: dict) -> bytes:
    t = ident["type"]
    if t == "SUCI":
        ri = ident.get("routingIndicator", "0000")
        d = [int(c) for c in ri] + [0xF] * (4 - len(ri))
        out = bytes([0x01]) + plmn_bytes(ident["mcc"], ident["mnc"]) + bytes(
            [(d[1] << 4) | d[0], (d[3] << 4) | d[2], ident.get("protectionSchemeId", 0) & 0xF,
             ident.get("homeNetworkPublicKeyId", 0)])
        return out + (bcd(ident["msin"]) if ident.get("protectionSchemeId", 0) == 0 else bytes.fromhex(ident["schemeOutput"]))
    if t == "5G-GUTI":
        return (bytes([0xF2]) + plmn_bytes(ident["mcc"], ident["mnc"]) + bytes(
            [ident["amfRegionId"], ident["amfSetId"] >> 2, ((ident["amfSetId"] & 3) << 6) | ident["amfPointer"]])
                + ident["tmsi"].to_bytes(4, "big"))
    if t == "5G-S-TMSI":
        return bytes([0xF4, ident["amfSetId"] >> 2, ((ident["amfSetId"] & 3) << 6) | ident["amfPointer"]]) + ident[
            "tmsi"].to_bytes(4, "big")
    if t in ("IMEI", "IMEISV"):
        digits = ident["digits"]
        odd = len(digits) % 2
        return bytes([(int(digits[0]) << 4) | (odd << 3) | (3 if t == "IMEI" else 5)]) + bcd(digits[1:])
    if t == "no identity":
        return b"\x00"
    raise ValueError(f"unknown identity type {t}")


def decode_identity(v: bytes) -> dict:
    if not v:
        raise NasDecodeError("empty mobile identity")
    t = v[0] & 7
    if t == 0:
        return {"type": "no identity"}
    if t == 1:
        if (v[0] >> 4) & 7 != 0:
            raise NasDecodeError("SUCI: only SUPI format IMSI supported")
        if len(v) < 8:
            raise NasDecodeError("SUCI too short")
        mcc, mnc = plmn_from(v[1:4])
        ri = ""
        for x in (v[4] & 0xF, v[4] >> 4, v[5] & 0xF, v[5] >> 4):
            if x == 0xF:
                break
            ri += str(x)
        out = {"type": "SUCI", "mcc": mcc, "mnc": mnc, "routingIndicator": ri,
               "protectionSchemeId": v[6] & 0xF, "homeNetworkPublicKeyId": v[7]}
        if out["protectionSchemeId"] == 0:
            out["msin"] = unbcd(v[8:])
        else:
            out["schemeOutput"] = v[8:].hex()
        return out
    if t == 2:
        if len(v) != 11:
            raise NasDecodeError("5G-GUTI length must be 11")
        mcc, mnc = plmn_from(v[1:4])
        return {"type": "5G-GUTI", "mcc": mcc, "mnc": mnc, "amfRegionId": v[4], "amfSetId": (v[5] << 2) | (v[6] >> 6),
                "amfPointer": v[6] & 0x3F, "tmsi": int.from_bytes(v[7:11], "big")}
    if t == 4:
        if len(v) != 7:
            raise NasDecodeError("5G-S-TMSI length must be 7")
        return {"type": "5G-S-TMSI", "amfSetId": (v[1] << 2) | (v[2] >> 6), "amfPointer": v[2] & 0x3F,
                "tmsi": int.from_bytes(v[3:7], "big")}
    if t in (3, 5):
        digits = str(v[0] >> 4) + unbcd(v[1:])
        return {"type": "IMEI" if t == 3 else "IMEISV", "digits": digits}
    raise NasDecodeError(f"unsupported type of identity {t}")


def encode_nssai(lst: list[dict]) -> bytes:
    out = bytearray()
    for s in lst:
        if "sd" in s:
            out += bytes([4, s["sst"]]) + s["sd"].to_bytes(3, "big")
        else:
            out += bytes([1, s["sst"]])
    return bytes(out)


def decode_nssai(v: bytes) -> list[dict]:
    out, i = [], 0
    while i < len(v):
        n = v[i]
        i += 1
        if n not in (1, 2, 4, 5, 8) or i + n > len(v):
            raise NasDecodeError("malformed S-NSSAI")
        e = {"sst": v[i]}
        if n >= 4:
            e["sd"] = int.from_bytes(v[i + 1 : i + 4], "big")
        out.append(e)
        i += n
    return out


def encode_tai_list(tais: list[dict]) -> bytes:
    """Single type-00 partial list (all TAIs in one PLMN)."""
    mcc, mnc = tais[0]["mcc"], tais[0]["mnc"]
    return bytes([len(tais) - 1]) + plmn_bytes(mcc, mnc) + b"".join(t["tac"].to_bytes(3, "big") for t in tais)


def decode_tai_list(v: bytes) -> list[dict]:
    out, i = [], 0
    while i < len(v):
        hdr = v[i]
        i += 1
        typ, n = (hdr >> 5) & 3, (hdr & 0x1F) + 1
        if typ == 0:
            if i + 3 + 3 * n > len(v):
                raise NasDecodeError("TAI list truncated")
            mcc, mnc = plmn_from(v[i : i + 3])
            i += 3
            for _ in range(n):
                out.append({"mcc": mcc, "mnc": mnc, "tac": int.from_bytes(v[i : i + 3], "big")})
                i += 3
        elif typ == 1:
            if i + 6 > len(v):
                raise NasDecodeError("TAI list truncated")
            mcc, mnc = plmn_from(v[i : i + 3])
            first = int.from_bytes(v[i + 3 : i + 6], "big")
            out += [{"mcc": mcc, "mnc": mnc, "tac": (first + k) & 0xFFFFFF} for k in range(n)]
            i += 6
        elif typ == 2:
            if i + 6 * n > len(v):
                raise NasDecodeError("TAI list truncated")
            for _ in range(n):
                mcc, mnc = plmn_from(v[i : i + 3])
                out.append({"mcc": mcc, "mnc": mnc, "tac": int.from_bytes(v[i + 3 : i + 6], "big")})
                i += 6
        else:
            raise NasDecodeError("reserved TAI list type")
    if not out:
        raise NasDecodeError("empty TAI list")
    return out


# ---- encoding ---------------------------------------------------------------------------------


def _lv(v: bytes) -> bytes:
    return bytes([len(v)]) + v


def _lve(v: bytes) -> bytes:
    return len(v).to_bytes(2, "big") + v


def _tlv(iei: int, v: bytes) -> bytes:
    return bytes([iei]) + _lv(v)


def _tlve(iei: int, v: bytes) -> bytes:
    return bytes([iei]) + _lve(v)


def _ksi(k: dict) -> int:
    return ((k.get("tsc", 0) & 1) << 3) | (k.get("ksi", 7) & 7)


def _timer(t: dict) -> bytes:
    return bytes([((t["unit"] & 7) << 5) | (t["value"] & 0x1F)])


def encode(msg: dict, extra_ies: bytes = b"") -> bytes:
    name, b = msg["message"], msg.get("body", {})
    out = bytearray([EPD_5GMM, 0x00, CODES[name]])
    if name == "RegistrationRequest":
        rt = b.get("5gsRegistrationType", {"for": 0, "value": 1})
        out.append((_ksi(b.get("ngKSI", {})) << 4) | (rt.get("for", 0) << 3) | rt["value"])
        out += _lve(encode_identity(b["mobileIdentity"]))
        if "5gmmCapability" in b:
            out += _tlv(0x10, bytes.fromhex(b["5gmmCapability"]))
        if "ueSecurityCapability" in b:
            c = b["ueSecurityCapability"]
            out += _tlv(0x2E, bytes([c["5G-EA"], c["5G-IA"]]))
        if "requestedNSSAI" in b:
            out += _tlv(0x2F, encode_nssai(b["requestedNSSAI"]))
        if "nasMessageContainer" in b:
            out += _tlve(0x71, bytes.fromhex(b["nasMessageContainer"]))
    elif name == "RegistrationAccept":
        out += _lv(bytes([b.get("5gsRegistrationResult", 1)]))
        if "5gGuti" in b:
            out += _tlve(0x77, encode_identity(b["5gGuti"]))
        if "taiList" in b:
            out += _tlv(0x54, encode_tai_list(b["taiList"]))
        if "allowedNSSAI" in b:
            out += _tlv(0x15, encode_nssai(b["allowedNSSAI"]))
        if "t3512" in b:
            out += _tlv(0x5E, _timer(b["t3512"]))
        if "t3502" in b:
            out += _tlv(0x16, _timer(b["t3502"]))
    elif name == "RegistrationReject":
        out.append(b["5gmmCause"])
        if "t3346" in b:
            out += _tlv(0x5F, _timer(b["t3346"]))
        if "t3502" in b:
            out += _tlv(0x16, _timer(b["t3502"]))
    elif name == "DeregistrationRequest(UE originating)":
        out.append((_ksi(b.get("ngKSI", {})) << 4) | (b.get("switchOff", 0) << 3) | b.get("accessType", 1))
        out += _lve(encode_identity(b["mobileIdentity"]))
    elif name == "AuthenticationRequest":
        out.append(_ksi(b.get("ngKSI", {"ksi": 0})))
        out += _lv(bytes.fromhex(b.get("abba", "0000")))
        if "rand" in b:
            out += bytes([0x21]) + bytes.fromhex(b["rand"])
        if "autn" in b:
            out += _tlv(0x20, bytes.fromhex(b["autn"]))
    elif name == "AuthenticationResponse":
        if "resStar" in b:
            out += _tlv(0x2D, bytes.fromhex(b["resStar"]))
    elif name == "AuthenticationFailure":
        out.append(b["5gmmCause"])
        if "auts" in b:
            out += _tlv(0x30, bytes.fromhex(b["auts"]))
    elif name == "IdentityRequest":
        out.append(b.get("identityType", 1) & 7)
    elif name == "IdentityResponse":
        out += _lve(encode_identity(b["mobileIdentity"]))
    elif name == "SecurityModeCommand":
        a = b["selectedNasSecurityAlgorithms"]
        out.append(((a["ciphering"] & 0xF) << 4) | (a["integrity"] & 0xF))
        out.append(_ksi(b.get("ngKSI", {"ksi": 0})))
        c = b["replayedUeSecurityCapabilities"]
        out += _lv(bytes([c["5G-EA"], c["5G-IA"]]))
        if "imeisvRequest" in b:
            out.append(0xE0 | (1 if b["imeisvRequest"] else 0))
        if "additional5gSecurityInformation" in b:
            out += _tlv(0x36, bytes([b["additional5gSecurityInformation"]]))
    elif name == "SecurityModeComplete":
        if "imeisv" in b:
            out += _tlve(0x77, encode_identity(b["imeisv"]))
        if "nasMessageContainer" in b:
            out += _tlve(0x71, bytes.fromhex(b["nasMessageContainer"]))
    elif name in ("SecurityModeReject", "5GMMStatus"):
        out.append(b["5gmmCause"])
    elif name in ("RegistrationComplete", "DeregistrationAccept(UE originating)", "AuthenticationReject"):
        pass
    else:
        raise ValueError(f"cannot encode {name}")
    return bytes(out) + extra_ies


# ---- decoding ---------------------------------------------------------------------------------


class _Reader:
    def __init__(self, data: bytes, spans: dict):
        self.d, self.i, self.spans = data, 3, spans

    def empty(self) -> bool:
        return self.i >= len(self.d)

    def u8(self, what: str) -> int:
        if self.i >= len(self.d):
            raise NasDecodeError(f"{what}: message truncated")
        v = self.d[self.i]
        self.i += 1
        return v

    def take(self, n: int, what: str) -> bytes:
        if self.i + n > len(self.d):
            raise NasDecodeError(f"{what}: IE overruns message")
        v = self.d[self.i : self.i + n]
        self.i += n
        return v

    def lv(self, what: str) -> bytes:
        return self.take(self.u8(what), what)

    def lve(self, what: str) -> bytes:
        n = (self.u8(what) << 8) | self.u8(what)
        return self.take(n, what)

    def span(self, name: str, start: int) -> None:
        self.spans[name] = (start, self.i)


def _optionals(r: _Reader, handlers: dict):
    """Generic optional-IE loop; unknown IEs are skipped per TS 24.007 §11.2.4."""
    seen = set()
    while not r.empty():
        start = r.i
        first = r.d[r.i]
        key = first & 0xF0 if first & 0x80 else first
        if key in handlers and key not in seen:
            seen.add(key)
            name = handlers[key](r)
            r.span(f"body.{name}", start)
            continue
        r.u8("IEI")
        if first & 0x80:
            continue
        if first & 0xF0 == 0x70:
            r.lve("unknown TLV-E IE")
        else:
            r.lv("unknown TLV IE")


def _fixed(v: bytes, n: int, what: str) -> bytes:
    if len(v) != n:
        raise NasDecodeError(f"{what}: length {len(v)}, expected {n}")
    return v


def _timer_json(o: int) -> dict:
    return {"unit": o >> 5, "value": o & 0x1F}


def _ksi_json(n: int) -> dict:
    return {"tsc": (n >> 3) & 1, "ksi": n & 7}


def security_header_type(pdu: bytes) -> int:
    if len(pdu) < 3:
        raise NasDecodeError("message too short", 111)
    if pdu[0] != EPD_5GMM:
        raise NasDecodeError("not a 5GMM message", 97)
    return pdu[1] & 0x0F


def decode(pdu: bytes) -> Decoded:
    """Decodes a plain 5GMM message. Raises NasDecodeError (with the 5GMM cause) on errors."""
    if security_header_type(pdu) != 0:
        raise NasDecodeError("security protected message passed to plain decoder", 111)
    code = pdu[2]
    if code not in TYPES:
        raise NasDecodeError(f"message type 0x{code:02x} not implemented", 97)
    name = TYPES[code]
    spans: dict = {"header": (0, 3)}
    body: dict = {}
    r = _Reader(pdu, spans)
    if name == "RegistrationRequest":
        s = r.i
        o = r.u8("registration type")
        if o & 7 in (0, 7):
            raise NasDecodeError("reserved registration type")
        body["5gsRegistrationType"] = {"for": (o >> 3) & 1, "value": o & 7}
        body["ngKSI"] = _ksi_json(o >> 4)
        r.span("body.5gsRegistrationType", s)
        s = r.i
        body["mobileIdentity"] = decode_identity(r.lve("mobile identity"))
        r.span("body.mobileIdentity", s)

        def cap(rr):
            rr.u8("IEI")
            v = rr.lv("5GMM capability")
            body["5gmmCapability"] = v.hex()
            return "5gmmCapability"

        def sec(rr):
            rr.u8("IEI")
            v = rr.lv("UE security capability")
            if not 2 <= len(v) <= 8:
                raise NasDecodeError("UE security capability length")
            body["ueSecurityCapability"] = {"5G-EA": v[0], "5G-IA": v[1]}
            return "ueSecurityCapability"

        def nssai(rr):
            rr.u8("IEI")
            body["requestedNSSAI"] = decode_nssai(rr.lv("requested NSSAI"))
            return "requestedNSSAI"

        def tai(rr):
            rr.u8("IEI")
            rr.take(6, "last visited TAI")
            return "lastVisitedRegisteredTAI"

        def container(rr):
            rr.u8("IEI")
            body["nasMessageContainer"] = rr.lve("NAS message container").hex()
            return "nasMessageContainer"

        _optionals(r, {0x10: cap, 0x2E: sec, 0x2F: nssai, 0x52: tai, 0x71: container})
    elif name == "RegistrationAccept":
        s = r.i
        res = r.lv("5GS registration result")
        if len(res) != 1:
            raise NasDecodeError("5GS registration result length")
        body["5gsRegistrationResult"] = res[0]
        r.span("body.5gsRegistrationResult", s)

        def guti(rr):
            rr.u8("IEI")
            ident = decode_identity(rr.lve("5G-GUTI"))
            if ident["type"] != "5G-GUTI":
                raise NasDecodeError("5G-GUTI IE without a 5G-GUTI")
            body["5gGuti"] = ident
            return "5gGuti"

        def tai(rr):
            rr.u8("IEI")
            body["taiList"] = decode_tai_list(rr.lv("TAI list"))
            return "taiList"

        def nssai(rr):
            rr.u8("IEI")
            body["allowedNSSAI"] = decode_nssai(rr.lv("allowed NSSAI"))
            return "allowedNSSAI"

        def t3512(rr):
            rr.u8("IEI")
            body["t3512"] = _timer_json(_fixed(rr.lv("T3512"), 1, "T3512 value")[0])
            return "t3512"

        def t3502(rr):
            rr.u8("IEI")
            body["t3502"] = _timer_json(_fixed(rr.lv("T3502"), 1, "T3502 value")[0])
            return "t3502"

        _optionals(r, {0x77: guti, 0x54: tai, 0x15: nssai, 0x5E: t3512, 0x16: t3502})
    elif name == "RegistrationReject":
        s = r.i
        body["5gmmCause"] = r.u8("5GMM cause")
        r.span("body.5gmmCause", s)

        def t3346(rr):
            rr.u8("IEI")
            body["t3346"] = _timer_json(_fixed(rr.lv("T3346"), 1, "T3346 value")[0])
            return "t3346"

        def t3502(rr):
            rr.u8("IEI")
            body["t3502"] = _timer_json(_fixed(rr.lv("T3502"), 1, "T3502 value")[0])
            return "t3502"

        _optionals(r, {0x5F: t3346, 0x16: t3502})
    elif name == "DeregistrationRequest(UE originating)":
        s = r.i
        o = r.u8("de-registration type")
        body["switchOff"] = (o >> 3) & 1
        body["accessType"] = o & 3
        body["ngKSI"] = _ksi_json(o >> 4)
        r.span("body.deregistrationType", s)
        s = r.i
        body["mobileIdentity"] = decode_identity(r.lve("mobile identity"))
        r.span("body.mobileIdentity", s)
    elif name == "AuthenticationRequest":
        body["ngKSI"] = _ksi_json(r.u8("ngKSI") & 0xF)
        abba = r.lv("ABBA")
        if len(abba) < 2:
            raise NasDecodeError("ABBA too short")
        body["abba"] = abba.hex()

        def rand(rr):
            rr.u8("IEI")
            body["rand"] = rr.take(16, "RAND").hex()
            return "rand"

        def autn(rr):
            rr.u8("IEI")
            body["autn"] = _fixed(rr.lv("AUTN"), 16, "AUTN").hex()
            return "autn"

        _optionals(r, {0x21: rand, 0x20: autn})
    elif name == "AuthenticationResponse":
        def res(rr):
            rr.u8("IEI")
            body["resStar"] = _fixed(rr.lv("RES*"), 16, "RES*").hex()
            return "resStar"

        _optionals(r, {0x2D: res})
    elif name == "AuthenticationFailure":
        s = r.i
        body["5gmmCause"] = r.u8("5GMM cause")
        r.span("body.5gmmCause", s)

        def auts(rr):
            rr.u8("IEI")
            body["auts"] = _fixed(rr.lv("AUTS"), 14, "AUTS").hex()
            return "auts"

        _optionals(r, {0x30: auts})
    elif name == "IdentityRequest":
        body["identityType"] = r.u8("identity type") & 7
    elif name == "IdentityResponse":
        s = r.i
        body["mobileIdentity"] = decode_identity(r.lve("mobile identity"))
        r.span("body.mobileIdentity", s)
    elif name == "SecurityModeCommand":
        o = r.u8("selected algorithms")
        body["selectedNasSecurityAlgorithms"] = {"ciphering": o >> 4, "integrity": o & 0xF}
        body["ngKSI"] = _ksi_json(r.u8("ngKSI") & 0xF)
        c = r.lv("replayed UE security capabilities")
        if len(c) < 2:
            raise NasDecodeError("replayed UE security capabilities length")
        body["replayedUeSecurityCapabilities"] = {"5G-EA": c[0], "5G-IA": c[1]}

        def imeisv(rr):
            body["imeisvRequest"] = (rr.u8("IMEISV request") & 7) == 1
            return "imeisvRequest"

        def add(rr):
            rr.u8("IEI")
            body["additional5gSecurityInformation"] = _fixed(rr.lv("additional info"), 1, "additional info")[0]
            return "additional5gSecurityInformation"

        _optionals(r, {0xE0: imeisv, 0x36: add})
    elif name == "SecurityModeComplete":
        def imeisv(rr):
            rr.u8("IEI")
            body["imeisv"] = decode_identity(rr.lve("IMEISV"))
            return "imeisv"

        def container(rr):
            rr.u8("IEI")
            body["nasMessageContainer"] = rr.lve("NAS message container").hex()
            return "nasMessageContainer"

        _optionals(r, {0x77: imeisv, 0x71: container})
    elif name in ("SecurityModeReject", "5GMMStatus"):
        s = r.i
        body["5gmmCause"] = r.u8("5GMM cause")
        r.span("body.5gmmCause", s)
    else:  # messages without mandatory IEs
        _optionals(r, {})
    return Decoded({"message": name, "body": body}, spans)


# ---- convenience constructors -------------------------------------------------------------------


def authentication_request(ngksi: int, rand: bytes, autn: bytes, abba: bytes = b"\x00\x00") -> dict:
    return {"message": "AuthenticationRequest",
            "body": {"ngKSI": {"tsc": 0, "ksi": ngksi}, "abba": abba.hex(), "rand": rand.hex(), "autn": autn.hex()}}


def security_mode_command(ea: int, ia: int, ngksi: int, caps: dict, imeisv_request: bool | None = None,
                          additional: int | None = None) -> dict:
    body = {"selectedNasSecurityAlgorithms": {"ciphering": ea, "integrity": ia}, "ngKSI": {"tsc": 0, "ksi": ngksi},
            "replayedUeSecurityCapabilities": caps}
    if imeisv_request is not None:
        body["imeisvRequest"] = imeisv_request
    if additional is not None:
        body["additional5gSecurityInformation"] = additional
    return {"message": "SecurityModeCommand", "body": body}


def registration_accept(guti: dict | None, tac: int = 1, t3512: dict | None = None, nssai=None) -> dict:
    body: dict = {"5gsRegistrationResult": 1}
    if guti is not None:
        body["5gGuti"] = guti
    body["taiList"] = [{"mcc": "001", "mnc": "01", "tac": tac}]
    body["allowedNSSAI"] = nssai if nssai is not None else [{"sst": 1}]
    if t3512 is not None:
        body["t3512"] = t3512
    return {"message": "RegistrationAccept", "body": body}


def registration_reject(cause: int, t3346: dict | None = None) -> dict:
    body: dict = {"5gmmCause": cause}
    if t3346 is not None:
        body["t3346"] = t3346
    return {"message": "RegistrationReject", "body": body}


def plain(name: str, **body) -> dict:
    return {"message": name, "body": body}
