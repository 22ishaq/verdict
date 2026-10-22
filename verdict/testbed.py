"""Full-stack testbed (UE + gNB + AMF from NR-Lite) with fault injection, and a UE emulator that
lets Verdict play the UE towards NR-Lite's gNB and AMF.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Callable

from verdict import _nrlite
from verdict.codec import nas, rrc
from verdict.codec import security as sec
from verdict.ss import TEST_K, TEST_OPC, TEST_SUPI
from verdict.templates import Mismatch, match
from verdict.verdicts import Verdict, VerdictError


def describe_air(p: dict) -> str:
    """Summary of an air-interface PDU decoded with Verdict's codecs (PDCP assumed unciphered)."""
    channel = f"{p['direction']}-{p['channel']}"
    data = p["data"] if p["channel"] == "CCCH" else p["data"][2:-4]
    try:
        m = rrc.decode(channel, data).message
    except ValueError:
        return f"{channel} <undecodable>"
    name = m["message"]
    nas_hex = m["body"].get("dedicatedNAS-Message")
    if nas_hex:
        raw = bytes.fromhex(nas_hex)
        try:
            sht = nas.security_header_type(raw)
            inner = nas.decode(raw if sht == 0 else raw[7:]).name
        except ValueError:
            inner = "<NAS>"
        name += f" [{inner}]"
    return name


class Testbed:
    def __init__(self, seed: int = 1, n_ues: int = 1, gnb: dict | None = None, amf: dict | None = None,
                 log_level: str = "info", pcap_path: str | None = None):
        self.sim = _nrlite.Simulator(seed=seed, log_level=log_level, gnb=gnb or {}, amf=amf or {})
        for _ in range(n_ues):
            self.sim.add_ue()
        if pcap_path:
            self.sim.start_pcap(pcap_path)
        self.injections: list[str] = []
        self._rules: list[Callable[[dict], object]] = []
        self.sim.set_air_interceptor(self._intercept)

    def close(self) -> None:
        self.sim.stop_pcap()

    # ---- fault injection -------------------------------------------------------------------------

    def _intercept(self, p: dict):
        for rule in list(self._rules):
            r = rule(p)
            if r is not None:
                return r
        return None

    def _once(self, needle: str, action, direction: str | None, label: str):
        state = {"done": False}

        def rule(p):
            if state["done"] or (direction and p["direction"] != direction):
                return None
            summary = describe_air(p)
            if needle in summary:
                state["done"] = True
                self.injections.append(f"t={self.sim.now()} {label} {summary}")
                return action(p)
            return None

        self._rules.append(rule)

    def drop_first(self, needle: str, direction: str | None = None) -> None:
        self._once(needle, lambda p: "drop", direction, "dropped")

    def delay_first(self, needle: str, ms: int, direction: str | None = None) -> None:
        self._once(needle, lambda p: ms, direction, f"delayed {ms} ms")

    def corrupt_first(self, needle: str, fn: Callable[[bytes], bytes], direction: str | None = None) -> None:
        self._once(needle, lambda p: fn(p["data"]), direction, "corrupted")

    def duplicate_first(self, needle: str, direction: str = "DL") -> None:
        def action(p):
            self.sim.inject_dl(p["rnti"], p["channel"], p["data"]) if direction == "DL" else \
                self.sim.inject_ul(p["rnti"], p["channel"], p["data"])
            return None

        self._once(needle, action, direction, "duplicated")

    # ---- convenience -----------------------------------------------------------------------------

    def register_all(self) -> None:
        for i in range(self.sim.ue_count()):
            self.sim.ue_power_on(i)
            self.sim.ue_register(i)

    def advance(self, ms: int) -> None:
        self.sim.advance(ms)

    def ue(self, i: int = 0) -> dict:
        return self.sim.ue_state(i)

    def amf_view(self, i: int = 0) -> dict:
        return self.sim.amf_ue(self.ue(i)["supi"])

    def registered(self, i: int = 0) -> bool:
        return self.ue(i)["mm"] == "5GMM-REGISTERED" and self.amf_view(i).get("state") == "5GMM-REGISTERED"

    def uu_messages(self) -> list[str]:
        return [r["message"] for r in self.sim.trace() if r["iface"] == "Uu" and not r["dropped"]]


@dataclass
class DlPdu:
    time: int
    channel: str
    rrc: dict | None
    nas: dict | None
    nas_raw: bytes | None
    error: str | None = None


class UeEmulator:
    """Verdict playing the UE: talks to NR-Lite's gNB and AMF through the air interface."""

    def __init__(self, seed: int = 1, rnti: int = 0x7001, amf: dict | None = None, gnb: dict | None = None,
                 log_level: str = "info"):
        self.sim = _nrlite.Simulator(seed=seed, log_level=log_level, gnb=gnb or {}, amf=amf or {})
        self.sim.amf_add_subscriber(TEST_SUPI, TEST_K, TEST_OPC, 0)
        self.sim.set_downlink_handler(self._on_dl)
        self.rnti = rnti
        self.inbox: deque[DlPdu] = deque()
        self.pdcp = sec.PdcpSrb(1, sec.UPLINK)
        self.nas_ctx: sec.NasContext | None = None
        self.kamf: bytes | None = None
        self.sqn_ms = 0

    def fail(self, reason: str, **kw):
        raise VerdictError(Verdict.FAIL, reason, **kw)

    def _on_dl(self, p: dict) -> None:
        channel = f"DL-{p['channel']}"
        try:
            data = p["data"]
            if p["channel"] == "DCCH":
                data, _, _ = self.pdcp.unwrap(data)
            m = rrc.decode(channel, data).message
        except ValueError as e:
            self.inbox.append(DlPdu(self.sim.now(), channel, None, None, None, str(e)))
            return
        raw = bytes.fromhex(m["body"]["dedicatedNAS-Message"]) if "dedicatedNAS-Message" in m["body"] else None
        nas_msg = None
        if raw is not None:
            sht = raw[1] & 0xF
            plain = raw
            if sht in (1, 2) and self.nas_ctx is not None:
                plain, _ = self.nas_ctx.unprotect(raw, sec.DOWNLINK)
            elif sht == 3:
                plain = raw[7:]
            nas_msg = nas.decode(plain).message
        self.inbox.append(DlPdu(self.sim.now(), channel, m, nas_msg, raw))

    def send_ccch(self, msg: dict | bytes) -> None:
        data = rrc.encode("UL-CCCH", msg) if isinstance(msg, dict) else msg
        self.sim.inject_ul(self.rnti, "CCCH", data)

    def send_dcch(self, msg: dict | bytes) -> None:
        data = rrc.encode("UL-DCCH", msg) if isinstance(msg, dict) else msg
        self.sim.inject_ul(self.rnti, "DCCH", self.pdcp.wrap(data), data)

    def send_nas(self, pdu: bytes) -> None:
        self.send_dcch({"message": "ulInformationTransfer", "body": {"dedicatedNAS-Message": pdu.hex()}})

    def expect(self, rrc_template: dict | None = None, nas_template: dict | None = None, within_ms: int = 500) -> DlPdu:
        if not self.inbox:
            self.sim.run_until(lambda: len(self.inbox) > 0, within_ms)
        if not self.inbox:
            self.fail(f"no downlink message within {within_ms} ms")
        pdu = self.inbox.popleft()
        mism: list[Mismatch] = []
        if rrc_template is not None:
            mism += match(rrc_template, pdu.rrc, "rrc")
        if nas_template is not None:
            mism += match(nas_template, pdu.nas, "nas")
        if mism:
            self.fail("unexpected downlink message: " + "; ".join(map(str, mism)))
        return pdu

    def expect_silence(self, within_ms: int) -> None:
        self.sim.run_until(lambda: len(self.inbox) > 0, within_ms)
        if self.inbox:
            self.fail(f"unexpected downlink message {self.inbox[0].rrc}")

    # ---- procedures ------------------------------------------------------------------------------

    def registration_request(self, with_caps: bool = True) -> dict:
        body = {"5gsRegistrationType": {"for": 0, "value": 1}, "ngKSI": {"tsc": 0, "ksi": 7},
                "mobileIdentity": {"type": "SUCI", "mcc": "001", "mnc": "01", "routingIndicator": "0000",
                                   "protectionSchemeId": 0, "homeNetworkPublicKeyId": 0, "msin": TEST_SUPI[5:]},
                "requestedNSSAI": [{"sst": 1}]}
        if with_caps:
            body["ueSecurityCapability"] = {"5G-EA": 0xA0, "5G-IA": 0x20}
        return {"message": "RegistrationRequest", "body": body}

    def connect(self, nas_pdu: bytes) -> DlPdu:
        self.send_ccch({"message": "rrcSetupRequest", "body": {"ue-Identity": {"randomValue": 12345},
                                                               "establishmentCause": "mo-Signalling"}})
        setup = self.expect({"message": "rrcSetup"})
        self.pdcp = sec.PdcpSrb(1, sec.UPLINK)
        self.send_dcch({"message": "rrcSetupComplete", "body": {
            "rrc-TransactionIdentifier": setup.rrc["body"]["rrc-TransactionIdentifier"], "selectedPLMN-Identity": 1,
            "dedicatedNAS-Message": nas_pdu.hex()}})
        return setup

    def answer_authentication(self, req: dict) -> bytes:
        b = req["body"]
        rand, autn = bytes.fromhex(b["rand"]), bytes.fromhex(b["autn"])
        m = sec.milenage(TEST_K, TEST_OPC, rand)
        sqn = bytes(x ^ y for x, y in zip(autn[:6], m["ak"]))
        if sec.milenage(TEST_K, TEST_OPC, rand, sqn, autn[6:8])["mac_a"] != autn[8:]:
            self.fail("network AUTN failed verification")
        self.sqn_ms = int.from_bytes(sqn, "big")
        snn = sec.serving_network_name()
        ckik = m["ck"] + m["ik"]
        res_star = sec.kdf(ckik, 0x6B, snn.encode(), rand, m["res"])[16:]
        kausf = sec.kdf(ckik, 0x6A, snn.encode(), autn[:6])
        self.kamf = sec.derive_kamf(sec.kdf(kausf, 0x6C, snn.encode()), TEST_SUPI, bytes.fromhex(b["abba"]))
        return nas.encode({"message": "AuthenticationResponse", "body": {"resStar": res_star.hex()}})

    def answer_security_mode(self, smc: DlPdu) -> bytes:
        b = smc.nas["body"]
        alg = b["selectedNasSecurityAlgorithms"]
        self.nas_ctx = sec.NasContext(self.kamf, alg["ciphering"], alg["integrity"], b["ngKSI"]["ksi"])
        self.nas_ctx.unprotect(smc.nas_raw, sec.DOWNLINK)
        return self.nas_ctx.protect(nas.encode({"message": "SecurityModeComplete", "body": {}}), sec.INT_CIPH_NEW,
                                    sec.UPLINK)

    def register(self) -> None:
        """Runs the UE side of initial registration up to and including Registration Complete."""
        self.connect(nas.encode(self.registration_request()))
        auth = self.expect(nas_template={"message": "AuthenticationRequest"})
        self.send_nas(self.answer_authentication(auth.nas))
        smc = self.expect(nas_template={"message": "SecurityModeCommand"})
        complete = self.answer_security_mode(smc)
        kgnb = sec.derive_kgnb(self.kamf, self.nas_ctx.ul_count - 1)
        self.send_nas(complete)
        as_smc = self.expect({"message": "securityModeCommand"})
        k_int = sec.algorithm_key(kgnb, sec.RRC_INT, 2)
        self.pdcp.tx_int = k_int
        self.send_dcch({"message": "securityModeComplete",
                        "body": {"rrc-TransactionIdentifier": as_smc.rrc["body"]["rrc-TransactionIdentifier"]}})
        self.pdcp.rx_int = k_int
        self.expect(nas_template={"message": "RegistrationAccept"})
        self.send_nas(self.nas_ctx.protect(nas.encode({"message": "RegistrationComplete", "body": {}}), sec.INT_CIPH,
                                           sec.UPLINK))
        self.settle()

    def settle(self, ms: int = 20) -> None:
        """Lets in-flight messages reach the network before the caller inspects its state."""
        self.sim.advance(ms)
