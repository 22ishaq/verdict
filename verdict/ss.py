"""System Simulator (SS): the test system that plays gNB + AMF towards the UE under test.

This follows the TS 38.523 model: the UE is the device under test, and the SS drives it with
downlink messages and checks every uplink message against a template. The SS uses only Verdict's
own codecs (verdict.codec) and security functions, never NR-Lite's.

Typical test body::

    with ss.preamble():
        ss.ue.power_on()
    with ss.step(1, "The UE is made to register"):
        ss.ue.register()
    with ss.step(2, "Check: the UE transmits RRCSetupRequest with cause mo-Signalling"):
        ss.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest", establishmentCause="mo-Signalling"))
"""

from __future__ import annotations

import random
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field

from verdict import _nrlite
from verdict.codec import nas, rrc
from verdict.codec import security as sec
from verdict.templates import ANY, Mismatch, OneOf, match, message
from verdict.verdicts import Verdict, VerdictError

TEST_SUPI = "001010000000001"
TEST_K = bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc")
TEST_OPC = bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf")
UE_CAPS = {"5G-EA": 0xA0, "5G-IA": 0x20}
PROTECTION = {0: "plain", 1: "integrity", 2: "integrity+ciphered", 3: "integrity, new context",
              4: "integrity+ciphered, new context"}


@dataclass
class NasView:
    raw: bytes
    protection: str = "plain"
    plain: bytes | None = None
    message: dict | None = None
    spans: dict = field(default_factory=dict)
    error: str | None = None
    integrity_ok: bool | None = None
    count: int | None = None

    @property
    def name(self) -> str:
        return self.message["message"] if self.message else "<undecodable NAS>"


@dataclass
class UlPdu:
    time: int
    channel: str
    raw: bytes
    rrc_bytes: bytes
    rrc: dict | None = None
    rrc_spans: dict = field(default_factory=dict)
    decode_error: str | None = None
    pdcp_count: int | None = None
    integrity_ok: bool | None = None
    nas: NasView | None = None

    @property
    def name(self) -> str:
        return self.rrc["message"] if self.rrc else "<undecodable RRC>"

    def summary(self) -> str:
        s = f"{self.channel} {self.name}"
        if self.nas is not None:
            s += f" [{self.nas.name}{'' if self.nas.protection == 'plain' else '*'}]"
        if self.integrity_ok is False:
            s += " (MAC-I invalid)"
        return s


class UeControl:
    """Trigger points of the UE under test (the equivalent of MMI / AT commands)."""

    def __init__(self, sim: _nrlite.Simulator, index: int):
        self._sim, self._i = sim, index

    def power_on(self) -> None:
        self._sim.ue_power_on(self._i)

    def power_off(self) -> None:
        self._sim.ue_power_off(self._i)

    def register(self) -> bool:
        return self._sim.ue_register(self._i)

    def deregister(self, switch_off: bool = False) -> bool:
        return self._sim.ue_deregister(self._i, switch_off)

    def set_usim_sqn(self, sqn: int) -> None:
        self._sim.ue_set_usim_sqn(self._i, sqn)

    @property
    def state(self) -> dict:
        return self._sim.ue_state(self._i)

    def timer(self, name: str) -> int | None:
        return self.state["timers"][name]


class SystemSimulator:
    def __init__(self, seed: int = 1, ue_options: dict | None = None, log_level: str = "info",
                 pcap_path: str | None = None):
        self.sim = _nrlite.Simulator(seed=seed, log_level=log_level)
        self.ue = UeControl(self.sim, self.sim.add_ue(provision=False, options=ue_options or {}))
        self.rnti = self.ue.state["rnti"]
        self.sim.detach_gnb(self._on_uplink)
        if pcap_path:
            self.sim.start_pcap(pcap_path)
        self.rng = random.Random(seed)
        self.inbox: deque[UlPdu] = deque()
        self.events: list[dict] = []
        self.step_label: str | None = None
        self.in_preamble = False

        self.pdcp = sec.PdcpSrb(1, sec.DOWNLINK)
        self.txid = 0
        self.supi, self.k, self.opc = TEST_SUPI, TEST_K, TEST_OPC
        self.sqn = 0
        self.snn = sec.serving_network_name("001", "01")
        self.av: sec.AuthVector | None = None
        self.kamf: bytes | None = None
        self.ngksi = 0
        self.nas_ctx: sec.NasContext | None = None
        self.pending_ctx: sec.NasContext | None = None
        self.kgnb_count: int | None = None
        self.krrc_int: bytes | None = None
        self.as_pending = False
        self.ue_caps = dict(UE_CAPS)
        self.guti: dict | None = None

    def close(self) -> None:
        self.sim.stop_pcap()

    # ---- verdict helpers ----------------------------------------------------------------------

    def fail(self, reason: str, **kw) -> None:
        raise VerdictError(Verdict.INCONC if self.in_preamble else Verdict.FAIL, reason, step=self.step_label,
                           capture=self.events, **kw)

    @contextmanager
    def preamble(self, text: str = "Preamble"):
        self.in_preamble, self.step_label = True, text
        try:
            yield
        except VerdictError as e:
            e.verdict = Verdict.INCONC
            raise
        finally:
            self.in_preamble, self.step_label = False, None

    @contextmanager
    def step(self, number: int | str, text: str):
        self.step_label = f"{number}: {text}"
        try:
            yield
        finally:
            self.step_label = None

    def check(self, condition: bool, reason: str) -> None:
        if not condition:
            self.fail(reason)

    def _record(self, direction: str, summary: str, pdu=None) -> None:
        self.events.append({"time": self.sim.now(), "dir": direction, "summary": summary,
                            "step": self.step_label, "pdu": pdu})

    # ---- uplink ------------------------------------------------------------------------------

    def _open_nas(self, raw: bytes) -> NasView:
        view = NasView(raw)
        try:
            sht = nas.security_header_type(raw)
        except nas.NasDecodeError as e:
            view.error = str(e)
            return view
        view.protection = PROTECTION.get(sht, f"reserved ({sht})")
        try:
            if sht == 0:
                view.plain = raw
            elif sht in (1, 2) and self.nas_ctx is not None:
                view.plain, view.count = self.nas_ctx.unprotect(raw, sec.UPLINK)
                view.integrity_ok = True
            elif sht == 4 and self.pending_ctx is not None:
                view.plain, view.count = self.pending_ctx.unprotect(raw, sec.UPLINK)
                view.integrity_ok = True
                self.nas_ctx, self.pending_ctx = self.pending_ctx, None
                self.kgnb_count = view.count
            else:
                view.integrity_ok = False
                view.error = "no NAS security context to verify the message"
                view.plain = raw[7:]
        except sec.IntegrityError as e:
            view.integrity_ok = False
            view.error = str(e)
            view.plain = raw[7:] if len(raw) > 7 else raw
        if view.plain is not None:
            try:
                d = nas.decode(view.plain)
                view.message, view.spans = d.message, d.spans
            except nas.NasDecodeError as e:
                view.error = (view.error + "; " if view.error else "") + f"NAS decode error: {e}"
        if view.integrity_ok and sht == 1 and view.message and view.message["message"] in (
                "RegistrationRequest", "DeregistrationRequest(UE originating)"):
            self.kgnb_count = view.count  # initial NAS message protected with an existing context
        return view

    def _on_uplink(self, p: dict) -> None:
        data: bytes = p["data"]
        if p["channel"] == "CCCH":
            pdu = UlPdu(self.sim.now(), "UL-CCCH", data, data)
        else:
            try:
                key = self.krrc_int if self.as_pending else None
                sdu, count, ok = self.pdcp.unwrap(data, verify_with=key)
            except sec.IntegrityError as e:
                pdu = UlPdu(self.sim.now(), "UL-DCCH", data, b"", decode_error=str(e))
                self.inbox.append(pdu)
                self._record("UL", pdu.summary(), pdu)
                return
            pdu = UlPdu(self.sim.now(), "UL-DCCH", data, sdu, pdcp_count=count, integrity_ok=ok)
        try:
            d = rrc.decode(pdu.channel, pdu.rrc_bytes)
            pdu.rrc, pdu.rrc_spans = d.message, d.spans
        except ValueError as e:
            pdu.decode_error = str(e)
        if pdu.rrc:
            nas_hex = pdu.rrc["body"].get("dedicatedNAS-Message")
            if nas_hex is not None:
                pdu.nas = self._open_nas(bytes.fromhex(nas_hex))
                if pdu.nas.message and pdu.nas.message["message"] == "RegistrationRequest":
                    caps = pdu.nas.message["body"].get("ueSecurityCapability")
                    if caps:
                        self.ue_caps = caps
        self.inbox.append(pdu)
        self._record("UL", pdu.summary(), pdu)

    # ---- downlink ----------------------------------------------------------------------------

    def next_txid(self) -> int:
        t = self.txid
        self.txid = (t + 1) % 4
        return t

    def send_dl_ccch(self, msg: dict | bytes, summary: str | None = None) -> None:
        data = rrc.encode("DL-CCCH", msg) if isinstance(msg, dict) else msg
        self.sim.inject_dl(self.rnti, "CCCH", data, data)
        self._record("DL", "DL-CCCH " + (summary or (msg["message"] if isinstance(msg, dict) else f"raw {data.hex()}")))

    def send_dl_dcch(self, msg: dict | bytes, summary: str | None = None, *, mac_override: bytes | None = None) -> bytes:
        rrc_bytes = rrc.encode("DL-DCCH", msg) if isinstance(msg, dict) else msg
        pdu = self.pdcp.wrap(rrc_bytes, mac_override=mac_override)
        self.sim.inject_dl(self.rnti, "DCCH", pdu, rrc_bytes)
        label = summary or (msg["message"] if isinstance(msg, dict) else f"raw {rrc_bytes.hex()}")
        self._record("DL", "DL-DCCH " + label)
        return pdu

    def send_dl_pdcp_raw(self, pdcp_pdu: bytes, summary: str) -> None:
        self.sim.inject_dl(self.rnti, "DCCH", pdcp_pdu)
        self._record("DL", "DL-DCCH " + summary)

    def send_nas(self, msg: dict | bytes, *, protection: str = "auto", extra_ies: bytes = b"",
                 summary: str | None = None) -> bytes:
        """Sends a NAS message in DLInformationTransfer.

        protection: 'auto' (integrity+ciphered once a context exists, else plain), 'plain',
        'integrity', 'integrity+ciphered'.
        """
        plain = nas.encode(msg, extra_ies) if isinstance(msg, dict) else msg
        if protection == "auto":
            protection = "integrity+ciphered" if self.nas_ctx else "plain"
        if protection == "plain":
            pdu = plain
        else:
            if self.nas_ctx is None:
                raise RuntimeError("no NAS security context in the SS")
            sht = sec.INT if protection == "integrity" else sec.INT_CIPH
            pdu = self.nas_ctx.protect(plain, sht, sec.DOWNLINK)
        name = summary or (msg["message"] if isinstance(msg, dict) else "raw NAS")
        self.send_dl_dcch(rrc.dl_information_transfer(self.next_txid(), pdu),
                          f"dlInformationTransfer [{name}{'' if protection == 'plain' else '*'}]")
        return pdu

    # ---- expectations ------------------------------------------------------------------------

    def _wait(self, within_ms: int) -> UlPdu | None:
        if not self.inbox:
            self.sim.run_until(lambda: len(self.inbox) > 0, within_ms)
        return self.inbox.popleft() if self.inbox else None

    def expect(self, *, channel: str | None = None, rrc: dict | None = None, nas: dict | None = None,
               within_ms: int = 1000, what: str = "") -> UlPdu:
        """The next uplink PDU must arrive within `within_ms` and match the templates."""
        what = what or (nas["message"] if nas else rrc["message"] if rrc else "an uplink message")
        pdu = self._wait(within_ms)
        if pdu is None:
            self.fail(f"no uplink message within {within_ms} ms", expected=what)
        mism: list[Mismatch] = []
        if channel and pdu.channel != channel:
            mism.append(Mismatch("channel", channel, pdu.channel))
        if pdu.decode_error:
            self.fail(f"the UE sent an undecodable message: {pdu.decode_error}", pdu=pdu, expected=what)
        if rrc is not None:
            mism += match(rrc, pdu.rrc, "rrc")
        if nas is not None:
            if pdu.nas is None:
                mism.append(Mismatch("nas", nas["message"], "<no NAS message>"))
            elif pdu.nas.message is None:
                mism.append(Mismatch("nas", nas["message"], pdu.nas.error or "<undecodable>"))
            else:
                mism += match(nas, pdu.nas.message, "nas")
                if pdu.nas.integrity_ok is False:
                    mism.append(Mismatch("nas.integrity", "valid MAC", pdu.nas.error or "invalid"))
        if mism:
            self.fail("the received message does not match the expected template", pdu=pdu, mismatches=mism,
                      expected=what)
        return pdu

    def expect_nas(self, template: dict, within_ms: int = 1000) -> UlPdu:
        carrier = {"message": OneOf("ulInformationTransfer", "rrcSetupComplete")}
        return self.expect(channel="UL-DCCH", rrc=carrier, nas=template, within_ms=within_ms,
                           what=f"{template['message']} in UL NAS transport")

    def expect_silence(self, within_ms: int, what: str = "no uplink message") -> None:
        """Check that the UE transmits nothing for `within_ms`."""
        pdu = self._wait(within_ms)
        if pdu is not None:
            self.fail(f"unexpected uplink message (expected {what})", pdu=pdu, expected=what)

    def advance(self, ms: int) -> None:
        self.sim.advance(ms)

    def drain(self) -> list[UlPdu]:
        out = list(self.inbox)
        self.inbox.clear()
        return out

    # ---- generic procedures (in the style of TS 38.508-1) -------------------------------------

    def connect(self, txid: int | None = None) -> UlPdu:
        """RRCSetupRequest -> RRCSetup -> RRCSetupComplete. Returns RRCSetupComplete."""
        self.expect(channel="UL-CCCH", rrc=message("rrcSetupRequest"), within_ms=2000, what="RRCSetupRequest")
        txid = self.answer_setup(txid)
        return self.expect(channel="UL-DCCH", rrc=message("rrcSetupComplete", **{"rrc-TransactionIdentifier": txid}),
                           what="RRCSetupComplete")

    def answer_setup(self, txid: int | None = None, srbs=(1,)) -> int:
        """Sends RRCSetup and resets the SS side of SRB1 (a new connection starts from COUNT 0)."""
        self.pdcp = sec.PdcpSrb(1, sec.DOWNLINK)
        self.krrc_int, self.as_pending = None, False
        txid = self.next_txid() if txid is None else txid
        self.send_dl_ccch(rrc.rrc_setup(txid, srbs))
        return txid

    def new_challenge(self, *, sqn: int | None = None, amf: bytes = b"\x80\x00", ngksi: int | None = None) -> dict:
        self.sqn = self.sqn + 1 if sqn is None else sqn
        rand = bytes(self.rng.getrandbits(8) for _ in range(16))
        self.av = sec.generate_av(self.k, self.opc, self.sqn, rand, self.snn, amf)
        if ngksi is not None:
            self.ngksi = ngksi
        return nas.authentication_request(self.ngksi, self.av.rand, self.av.autn)

    def authenticate(self, **kw) -> UlPdu:
        self.send_nas(self.new_challenge(**kw), summary="AuthenticationRequest")
        resp = self.expect_nas(message("AuthenticationResponse", resStar=ANY))
        if bytes.fromhex(resp.nas.message["body"]["resStar"]) != self.av.xres_star:
            self.fail("RES* does not match XRES*", pdu=resp)
        self.kamf = sec.derive_kamf(self.av.kseaf, self.supi)
        return resp

    def security_mode_command(self, ea: int = 0, ia: int = 2, *, caps: dict | None = None,
                              imeisv_request: bool | None = None, additional: int | None = None,
                              corrupt_mac: bool = False) -> bytes:
        self.pending_ctx = sec.NasContext(self.kamf, ea, ia, self.ngksi)
        smc = nas.security_mode_command(ea, ia, self.ngksi, caps or self.ue_caps, imeisv_request, additional)
        pdu = bytearray(self.pending_ctx.protect(nas.encode(smc), sec.INT_NEW, sec.DOWNLINK))
        if corrupt_mac:
            pdu[2] ^= 0xFF
        self.send_dl_dcch(rrc.dl_information_transfer(self.next_txid(), bytes(pdu)),
                          "dlInformationTransfer [SecurityModeCommand*]")
        return bytes(pdu)

    def nas_security(self, ea: int = 0, ia: int = 2, **kw) -> UlPdu:
        self.security_mode_command(ea, ia, **kw)
        complete = self.expect_nas(message("SecurityModeComplete"))
        if self.nas_ctx is None or complete.nas.protection != PROTECTION[4]:
            self.fail("SecurityModeComplete not protected with the new security context", pdu=complete)
        return complete

    def as_security(self, ciphering: str = "nea0") -> UlPdu:
        kgnb = sec.derive_kgnb(self.nas_ctx.kamf, self.kgnb_count)
        self.krrc_int = sec.algorithm_key(kgnb, sec.RRC_INT, 2)
        self.pdcp.tx_int = self.krrc_int
        self.as_pending = True
        txid = self.next_txid()
        self.send_dl_dcch(rrc.security_mode_command(txid, ciphering, "nia2"))
        complete = self.expect(channel="UL-DCCH", rrc=message("securityModeComplete", **{"rrc-TransactionIdentifier": txid}),
                               what="SecurityModeComplete")
        self.as_pending = False
        if complete.integrity_ok is not True:
            self.fail("SecurityModeComplete MAC-I does not verify with K_RRCint", pdu=complete)
        self.pdcp.rx_int = self.krrc_int
        if ciphering == "nea2":
            k_enc = sec.algorithm_key(kgnb, sec.RRC_ENC, 2)
            self.pdcp.tx_enc = self.pdcp.rx_enc = k_enc
        return complete

    def accept(self, *, t3512: dict | None = None, extra_ies: bytes = b"", expect_complete: bool = True) -> dict:
        tmsi = self.rng.getrandbits(32)
        self.guti = {"type": "5G-GUTI", "mcc": "001", "mnc": "01", "amfRegionId": 1, "amfSetId": 1, "amfPointer": 1,
                     "tmsi": tmsi}
        self.send_nas(nas.registration_accept(self.guti, t3512=t3512), extra_ies=extra_ies,
                      summary="RegistrationAccept")
        if expect_complete:
            self.expect_nas(message("RegistrationComplete"))
        return self.guti

    def release(self, wait_time: int | None = None) -> None:
        self.send_dl_dcch(rrc.rrc_release(self.next_txid(), wait_time))
        self.advance(100)

    def register(self, *, t3512: dict | None = None, release: bool = True) -> dict:
        """Complete initial registration: the generic 'UE registered' preamble."""
        self.ue.power_on()
        if not self.ue.register():
            self.fail("the UE refused to start registration")
        self.connect()
        self.authenticate()
        self.nas_security()
        self.as_security()
        guti = self.accept(t3512=t3512)
        if release:
            self.release()
        return guti
