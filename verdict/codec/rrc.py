"""NR RRC codec for the test system (TS 38.331 §6.2), independent of NR-Lite.

Messages are dicts in the same shape NR-Lite's ``to_json`` produces, so the two decoders can be
compared field by field::

    {"message": "rrcSetupRequest",
     "body": {"ue-Identity": {"randomValue": 123}, "establishmentCause": "mo-Signalling"}}

Bit strings are integers and octet strings are lower-case hex. ``decode`` returns the message and
the bit span of each field (paths like ``body.establishmentCause``).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from verdict.codec import per
from verdict.codec.per import BitReader, BitWriter, PerDecodeError

CAUSES = ("emergency", "highPriorityAccess", "mt-Access", "mo-Signalling", "mo-Data", "mo-VoiceCall",
          "mo-VideoCall", "mo-SMS", "mps-PriorityAccess", "mcs-PriorityAccess", "spare6", "spare5", "spare4",
          "spare3", "spare2", "spare1")
CIPHERING = ("nea0", "nea1", "nea2", "nea3", "spare4", "spare3", "spare2", "spare1")
INTEGRITY = ("nia0", "nia1", "nia2", "nia3", "spare4", "spare3", "spare2", "spare1")
UL_DCCH = ("measurementReport", "rrcReconfigurationComplete", "rrcSetupComplete", "rrcReestablishmentComplete",
           "rrcResumeComplete", "securityModeComplete", "securityModeFailure", "ulInformationTransfer",
           "locationMeasurementIndication", "ueCapabilityInformation", "counterCheckResponse",
           "ueAssistanceInformation", "failureInformation", "ulInformationTransferMRDC", "scgFailureInformation",
           "scgFailureInformationEUTRA")
DL_DCCH = ("rrcReconfiguration", "rrcResume", "rrcRelease", "rrcReestablishment", "securityModeCommand",
           "dlInformationTransfer", "ueCapabilityEnquiry", "counterCheck", "mobilityFromNRCommand",
           "dlDedicatedMessageSegment-r16", "ueInformationRequest-r16", "dlInformationTransferMRDC-r16",
           "loggedMeasurementConfiguration-r16", "spare3", "spare2", "spare1")


@dataclass
class Decoded:
    message: dict
    spans: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return self.message["message"]


class Unsupported(PerDecodeError):
    pass


# ---- encoding ---------------------------------------------------------------------------------


def _enc_critical(w: BitWriter) -> None:
    w.put(0, 1)  # criticalExtensions: the -IEs alternative


def encode(channel: str, msg: dict) -> bytes:
    """Encodes a message dict for the given logical channel ('DL-CCCH', 'UL-DCCH', ...)."""
    name, body = msg["message"], msg.get("body", {})
    w = BitWriter()
    w.put(0, 1)  # MessageType: c1
    if channel == "UL-CCCH":
        if name != "rrcSetupRequest":
            raise ValueError(f"{name} is not a UL-CCCH message")
        w.put(0, 2)
        ident = body["ue-Identity"]
        if "randomValue" in ident:
            w.put(1, 1)
            w.put(ident["randomValue"], 39)
        else:
            w.put(0, 1)
            w.put(ident["ng-5G-S-TMSI-Part1"], 39)
        w.put(CAUSES.index(body["establishmentCause"]), 4)
        w.put(0, 1)  # spare
    elif channel == "DL-CCCH":
        if name == "rrcReject":
            w.put(0, 2)
            _enc_critical(w)
            wait = body.get("waitTime")
            w.put(1 if wait is not None else 0, 1)
            w.put(0, 2)
            if wait is not None:
                per.put_int(w, wait, 1, 16)
        elif name == "rrcSetup":
            w.put(1, 2)
            per.put_int(w, body["rrc-TransactionIdentifier"], 0, 3)
            _enc_critical(w)
            w.put(0, 2)  # lateNonCriticalExtension, nonCriticalExtension absent
            _enc_radio_bearer_config(w, body.get("radioBearerConfig", {}))
            per.put_octets(w, encode_cell_group_config(body.get("masterCellGroup", {"cellGroupId": 0})))
        else:
            raise ValueError(f"{name} is not a DL-CCCH message")
    elif channel == "DL-DCCH":
        index = DL_DCCH.index(name)
        w.put(index, 4)
        per.put_int(w, body["rrc-TransactionIdentifier"], 0, 3)
        _enc_critical(w)
        if name == "securityModeCommand":
            alg = body["securityConfigSMC"]["securityAlgorithmConfig"]
            w.put(0, 2)        # SecurityModeCommand-IEs optionals
            w.put(0, 1)        # SecurityConfigSMC extension bit
            w.put(0, 1)        # SecurityAlgorithmConfig extension bit
            w.put(1 if "integrityProtAlgorithm" in alg else 0, 1)
            w.put(0, 1)
            w.put(CIPHERING.index(alg["cipheringAlgorithm"]), 3)
            if "integrityProtAlgorithm" in alg:
                w.put(0, 1)
                w.put(INTEGRITY.index(alg["integrityProtAlgorithm"]), 3)
        elif name == "dlInformationTransfer":
            nas = body.get("dedicatedNAS-Message")
            w.put(1 if nas is not None else 0, 1)
            w.put(0, 2)
            if nas is not None:
                per.put_octets(w, bytes.fromhex(nas))
        elif name == "rrcRelease":
            depri = body.get("deprioritisationReq")
            wait = body.get("waitTime")
            w.put(0, 3)
            w.put(1 if depri else 0, 1)
            w.put(0, 1)
            w.put(1 if wait is not None else 0, 1)
            if depri:
                w.put(("frequency", "nr").index(depri["deprioritisationType"]), 1)
                w.put(("min5", "min10", "min15", "min30").index(depri["deprioritisationTimer"]), 2)
            if wait is not None:
                w.put(0b10, 2)  # RRCRelease-v1540-IEs: waitTime present, no further extension
                per.put_int(w, wait, 1, 16)
        else:
            raise ValueError(f"{name} encoding not implemented")
    elif channel == "UL-DCCH":
        index = UL_DCCH.index(name)
        w.put(index, 4)
        if name in ("securityModeComplete", "securityModeFailure"):
            per.put_int(w, body["rrc-TransactionIdentifier"], 0, 3)
            _enc_critical(w)
            w.put(0, 2)
        elif name == "ulInformationTransfer":
            _enc_critical(w)
            nas = body.get("dedicatedNAS-Message")
            w.put(1 if nas is not None else 0, 1)
            w.put(0, 2)
            if nas is not None:
                per.put_octets(w, bytes.fromhex(nas))
        elif name == "rrcSetupComplete":
            per.put_int(w, body["rrc-TransactionIdentifier"], 0, 3)
            _enc_critical(w)
            tmsi = body.get("ng-5G-S-TMSI-Value")
            nssai = body.get("s-NSSAI-List")
            w.put(0, 1)  # registeredAMF
            w.put(0, 1)  # guami-Type
            w.put(1 if nssai else 0, 1)
            w.put(1 if tmsi else 0, 1)
            w.put(0, 2)
            per.put_int(w, body["selectedPLMN-Identity"], 1, 12)
            if nssai:
                per.put_int(w, len(nssai), 1, 8)
                for s in nssai:
                    if "sst-SD" in s:
                        w.put(1, 1)
                        w.put((s["sst-SD"]["sst"] << 24) | s["sst-SD"]["sd"], 32)
                    else:
                        w.put(0, 1)
                        w.put(s["sst"], 8)
            per.put_octets(w, bytes.fromhex(body["dedicatedNAS-Message"]))
            if tmsi:
                if "ng-5G-S-TMSI" in tmsi:
                    w.put(0, 1)
                    w.put(tmsi["ng-5G-S-TMSI"], 48)
                else:
                    w.put(1, 1)
                    w.put(tmsi["ng-5G-S-TMSI-Part2"], 9)
        else:
            raise ValueError(f"{name} encoding not implemented")
    else:
        raise ValueError(f"unknown channel {channel}")
    return w.to_bytes()


def _enc_radio_bearer_config(w: BitWriter, rb: dict) -> None:
    srbs = rb.get("srb-ToAddModList", [])
    w.put(0, 1)  # extension bit
    w.put(1 if srbs else 0, 1)
    w.put(1 if rb.get("srb3-ToRelease") else 0, 1)
    w.put(0, 3)  # drb-ToAddModList, drb-ToReleaseList, securityConfig
    if srbs:
        per.put_int(w, len(srbs), 1, 2)
        for s in srbs:
            w.put(0, 1)
            w.put(1 if s.get("reestablishPDCP") else 0, 1)
            w.put(1 if s.get("discardOnPDCP") else 0, 1)
            w.put(0, 1)
            per.put_int(w, s["srb-Identity"], 1, 3)


def encode_cell_group_config(cg: dict) -> bytes:
    w = BitWriter()
    rlc = cg.get("rlc-BearerToAddModList", [])
    w.put(0, 1)
    w.put(1 if rlc else 0, 1)
    w.put(0, 6)
    per.put_int(w, cg.get("cellGroupId", 0), 0, 3)
    if rlc:
        per.put_int(w, len(rlc), 1, 32)
        for b in rlc:
            served = b.get("servedRadioBearer")
            w.put(0, 1)
            w.put(1 if served else 0, 1)
            w.put(1 if b.get("reestablishRLC") else 0, 1)
            w.put(0, 2)
            per.put_int(w, b["logicalChannelIdentity"], 1, 32)
            if served:
                if "srb-Identity" in served:
                    w.put(0, 1)
                    per.put_int(w, served["srb-Identity"], 1, 3)
                else:
                    w.put(1, 1)
                    per.put_int(w, served["drb-Identity"], 1, 32)
    return w.to_bytes()


# ---- decoding ---------------------------------------------------------------------------------


def _expect_ies(r: BitReader, what: str) -> None:
    if r.get(1) != 0:
        raise Unsupported(f"{what}.criticalExtensionsFuture")


def _skip_late(r: BitReader) -> None:
    per.get_octets(r)


def _check_end(r: BitReader) -> None:
    if r.remaining >= 8:
        raise PerDecodeError(f"{r.remaining // 8} trailing octet(s)")


def decode(channel: str, data: bytes) -> Decoded:
    r = BitReader(data)
    out = Decoded({"message": "", "body": {}}, r.spans)
    body = out.message["body"]
    if r.get(1) != 0:
        raise Unsupported("messageClassExtension")
    if channel == "UL-CCCH":
        if r.get(2) != 0:
            raise Unsupported("UL-CCCH alternative other than rrcSetupRequest")
        out.message["message"] = "rrcSetupRequest"
        with r.field("body.ue-Identity"):
            kind = "ng-5G-S-TMSI-Part1" if r.get(1) == 0 else "randomValue"
            body["ue-Identity"] = {kind: r.get(39)}
        with r.field("body.establishmentCause"):
            body["establishmentCause"] = CAUSES[r.get(4)]
        r.get(1)
    elif channel == "DL-CCCH":
        c1 = r.get(2)
        if c1 == 0:
            out.message["message"] = "rrcReject"
            _expect_ies(r, "RRCReject")
            wait, late, _nce = r.get(1), r.get(1), r.get(1)
            if wait:
                with r.field("body.waitTime"):
                    body["waitTime"] = per.get_int(r, 1, 16)
            if late:
                _skip_late(r)
        elif c1 == 1:
            out.message["message"] = "rrcSetup"
            with r.field("body.rrc-TransactionIdentifier"):
                body["rrc-TransactionIdentifier"] = per.get_int(r, 0, 3)
            _expect_ies(r, "RRCSetup")
            late, nce = r.get(1), r.get(1)
            with r.field("body.radioBearerConfig"):
                body["radioBearerConfig"] = _dec_radio_bearer_config(r)
            with r.field("body.masterCellGroup"):
                cg = per.get_octets(r)
            body["masterCellGroup"] = decode_cell_group_config(cg)
            if late:
                _skip_late(r)
            if nce:
                raise Unsupported("RRCSetup-IEs.nonCriticalExtension")
        else:
            raise Unsupported(f"DL-CCCH c1 alternative {c1}")
    elif channel == "UL-DCCH":
        c1 = r.get(4)
        name = UL_DCCH[c1]
        out.message["message"] = name
        if name in ("securityModeComplete", "securityModeFailure"):
            with r.field("body.rrc-TransactionIdentifier"):
                body["rrc-TransactionIdentifier"] = per.get_int(r, 0, 3)
            _expect_ies(r, name)
            late, _nce = r.get(1), r.get(1)
            if late:
                _skip_late(r)
        elif name == "ulInformationTransfer":
            _expect_ies(r, name)
            nas, late, nce = r.get(1), r.get(1), r.get(1)
            if nas:
                with r.field("body.dedicatedNAS-Message"):
                    body["dedicatedNAS-Message"] = per.get_octets(r).hex()
            if late:
                _skip_late(r)
            if nce:
                raise Unsupported("ULInformationTransfer-IEs.nonCriticalExtension")
        elif name == "rrcSetupComplete":
            with r.field("body.rrc-TransactionIdentifier"):
                body["rrc-TransactionIdentifier"] = per.get_int(r, 0, 3)
            _expect_ies(r, name)
            amf, guami, nssai, tmsi, late, nce = (r.get(1) for _ in range(6))
            with r.field("body.selectedPLMN-Identity"):
                body["selectedPLMN-Identity"] = per.get_int(r, 1, 12)
            if amf:
                with r.field("body.registeredAMF"):
                    if r.get(1):  # plmn-Identity
                        if r.get(1):
                            for _ in range(3):
                                per.get_int(r, 0, 9)
                        for _ in range(per.get_int(r, 2, 3)):
                            per.get_int(r, 0, 9)
                    body["registeredAMF"] = {"amf-Identifier": r.get(24)}
            if guami:
                body["guami-Type"] = ("native", "mapped")[r.get(1)]
            if nssai:
                with r.field("body.s-NSSAI-List"):
                    lst = []
                    for _ in range(per.get_int(r, 1, 8)):
                        if r.get(1):
                            v = r.get(32)
                            lst.append({"sst-SD": {"sst": v >> 24, "sd": v & 0xFFFFFF}})
                        else:
                            lst.append({"sst": r.get(8)})
                    body["s-NSSAI-List"] = lst
            with r.field("body.dedicatedNAS-Message"):
                body["dedicatedNAS-Message"] = per.get_octets(r).hex()
            if tmsi:
                with r.field("body.ng-5G-S-TMSI-Value"):
                    if r.get(1) == 0:
                        body["ng-5G-S-TMSI-Value"] = {"ng-5G-S-TMSI": r.get(48)}
                    else:
                        body["ng-5G-S-TMSI-Value"] = {"ng-5G-S-TMSI-Part2": r.get(9)}
            if late:
                _skip_late(r)
            if nce:
                raise Unsupported("RRCSetupComplete-IEs.nonCriticalExtension")
        else:
            raise Unsupported(name)
    elif channel == "DL-DCCH":
        c1 = r.get(4)
        name = DL_DCCH[c1]
        out.message["message"] = name
        if name not in ("securityModeCommand", "dlInformationTransfer", "rrcRelease"):
            raise Unsupported(name)
        with r.field("body.rrc-TransactionIdentifier"):
            body["rrc-TransactionIdentifier"] = per.get_int(r, 0, 3)
        _expect_ies(r, name)
        if name == "securityModeCommand":
            late, _nce = r.get(1), r.get(1)
            smc_ext = r.get(1)
            alg_ext, integ = r.get(1), r.get(1)
            alg = {}
            with r.field("body.securityConfigSMC.securityAlgorithmConfig.cipheringAlgorithm"):
                if r.get(1):
                    raise Unsupported("cipheringAlgorithm extension value")
                alg["cipheringAlgorithm"] = CIPHERING[r.get(3)]
            if integ:
                with r.field("body.securityConfigSMC.securityAlgorithmConfig.integrityProtAlgorithm"):
                    if r.get(1):
                        raise Unsupported("integrityProtAlgorithm extension value")
                    alg["integrityProtAlgorithm"] = INTEGRITY[r.get(3)]
            if alg_ext:
                per.skip_extension_additions(r)
            if smc_ext:
                per.skip_extension_additions(r)
            if late:
                _skip_late(r)
            body["securityConfigSMC"] = {"securityAlgorithmConfig": alg}
        elif name == "dlInformationTransfer":
            nas, late, nce = r.get(1), r.get(1), r.get(1)
            if nas:
                with r.field("body.dedicatedNAS-Message"):
                    body["dedicatedNAS-Message"] = per.get_octets(r).hex()
            if late:
                _skip_late(r)
            if nce:
                raise Unsupported("DLInformationTransfer-IEs.nonCriticalExtension")
        else:  # rrcRelease
            redirected, reselection, suspend, depri, late, nce = (r.get(1) for _ in range(6))
            if redirected or reselection or suspend:
                raise Unsupported("RRCRelease redirection / priorities / suspendConfig")
            if depri:
                body["deprioritisationReq"] = {
                    "deprioritisationType": ("frequency", "nr")[r.get(1)],
                    "deprioritisationTimer": ("min5", "min10", "min15", "min30")[r.get(2)],
                }
            if late:
                _skip_late(r)
            if nce:
                wait, more = r.get(1), r.get(1)
                if wait:
                    with r.field("body.waitTime"):
                        body["waitTime"] = per.get_int(r, 1, 16)
                if more:
                    raise Unsupported("RRCRelease-v1610-IEs")
    else:
        raise ValueError(f"unknown channel {channel}")
    _check_end(r)
    return out


def _dec_radio_bearer_config(r: BitReader) -> dict:
    ext = r.get(1)
    srb, srb3, drb, drb_rel, sec = (r.get(1) for _ in range(5))
    rb: dict = {}
    if srb:
        lst = []
        for _ in range(per.get_int(r, 1, 2)):
            e_ext, reest, discard, pdcp = r.get(1), r.get(1), r.get(1), r.get(1)
            item = {"srb-Identity": per.get_int(r, 1, 3)}
            if reest:
                item["reestablishPDCP"] = "true"
            if discard:
                item["discardOnPDCP"] = "true"
            if pdcp:
                raise Unsupported("SRB-ToAddMod.pdcp-Config")
            if e_ext:
                per.skip_extension_additions(r)
            lst.append(item)
        rb["srb-ToAddModList"] = lst
    if srb3:
        rb["srb3-ToRelease"] = "true"
    if drb or drb_rel or sec:
        raise Unsupported("RadioBearerConfig DRB / securityConfig")
    if ext:
        per.skip_extension_additions(r)
    return rb


def decode_cell_group_config(data: bytes) -> dict:
    r = BitReader(data)
    ext = r.get(1)
    opts = [r.get(1) for _ in range(7)]
    cg: dict = {"cellGroupId": per.get_int(r, 0, 3)}
    if opts[0]:
        lst = []
        for _ in range(per.get_int(r, 1, 32)):
            b_ext, served, reest, rlc_cfg, mac_cfg = (r.get(1) for _ in range(5))
            item: dict = {"logicalChannelIdentity": per.get_int(r, 1, 32)}
            if served:
                if r.get(1) == 0:
                    item["servedRadioBearer"] = {"srb-Identity": per.get_int(r, 1, 3)}
                else:
                    item["servedRadioBearer"] = {"drb-Identity": per.get_int(r, 1, 32)}
            if reest:
                item["reestablishRLC"] = "true"
            if rlc_cfg or mac_cfg:
                raise Unsupported("RLC-BearerConfig rlc-Config / mac-LogicalChannelConfig")
            if b_ext:
                per.skip_extension_additions(r)
            lst.append(item)
        cg["rlc-BearerToAddModList"] = lst
    if any(opts[1:]):
        raise Unsupported("CellGroupConfig field not modelled")
    if ext:
        per.skip_extension_additions(r)
    _check_end(r)
    return cg


# ---- convenience constructors (used by test cases) ----------------------------------------------


def rrc_setup(txid: int = 0, srbs=(1,)) -> dict:
    return {"message": "rrcSetup", "body": {
        "rrc-TransactionIdentifier": txid,
        "radioBearerConfig": {"srb-ToAddModList": [{"srb-Identity": s} for s in srbs]} if srbs else {},
        "masterCellGroup": {"cellGroupId": 0, "rlc-BearerToAddModList": [
            {"logicalChannelIdentity": 1, "servedRadioBearer": {"srb-Identity": 1}}]},
    }}


def rrc_reject(wait_time: int | None = None) -> dict:
    return {"message": "rrcReject", "body": {} if wait_time is None else {"waitTime": wait_time}}


def security_mode_command(txid: int, ciphering: str = "nea0", integrity: str | None = "nia2") -> dict:
    alg = {"cipheringAlgorithm": ciphering}
    if integrity is not None:
        alg["integrityProtAlgorithm"] = integrity
    return {"message": "securityModeCommand",
            "body": {"rrc-TransactionIdentifier": txid, "securityConfigSMC": {"securityAlgorithmConfig": alg}}}


def dl_information_transfer(txid: int, nas: bytes | None) -> dict:
    body = {"rrc-TransactionIdentifier": txid}
    if nas is not None:
        body["dedicatedNAS-Message"] = nas.hex()
    return {"message": "dlInformationTransfer", "body": body}


def rrc_release(txid: int, wait_time: int | None = None) -> dict:
    body = {"rrc-TransactionIdentifier": txid}
    if wait_time is not None:
        body["waitTime"] = wait_time
    return {"message": "rrcRelease", "body": body}
