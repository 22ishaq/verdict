"""Minimal ASN.1 UPER (ITU-T X.691, unaligned) bit codec for the test system.

This is Verdict's own implementation, written separately from NR-Lite's C++ codec so that the
test system never uses the device under test to check itself. The reader records the bit range
of every named field so a failing field can be highlighted in the hex dump of a message.
"""

from __future__ import annotations

from contextlib import contextmanager


class PerDecodeError(ValueError):
    """Abstract syntax error found while decoding."""


class BitWriter:
    def __init__(self) -> None:
        self._value = 0
        self._bits = 0

    def put(self, value: int, nbits: int) -> None:
        if nbits == 0:
            return
        if value < 0 or value >> nbits:
            raise ValueError(f"value {value} does not fit in {nbits} bits")
        self._value = (self._value << nbits) | value
        self._bits += nbits

    def put_bytes(self, data: bytes) -> None:
        for b in data:
            self.put(b, 8)

    @property
    def bit_length(self) -> int:
        return self._bits

    def to_bytes(self) -> bytes:
        """Complete encoding: padded with zero bits to an octet boundary, never empty."""
        pad = (-self._bits) % 8
        n = (self._bits + pad) // 8
        if n == 0:
            return b"\x00"
        return (self._value << pad).to_bytes(n, "big")


class BitReader:
    def __init__(self, data: bytes, base_bit: int = 0, spans: dict | None = None) -> None:
        self.data = bytes(data)
        self.pos = 0
        self.base_bit = base_bit           # offset of this buffer inside the outer PDU (for spans)
        self.spans: dict[str, tuple[int, int]] = spans if spans is not None else {}

    @property
    def remaining(self) -> int:
        return len(self.data) * 8 - self.pos

    def get(self, nbits: int) -> int:
        if nbits == 0:
            return 0
        if nbits > self.remaining:
            raise PerDecodeError(f"end of data: need {nbits} bit(s) at bit {self.pos}, {self.remaining} left")
        v = 0
        for _ in range(nbits):
            byte = self.data[self.pos // 8]
            v = (v << 1) | ((byte >> (7 - self.pos % 8)) & 1)
            self.pos += 1
        return v

    def get_bytes(self, n: int) -> bytes:
        return bytes(self.get(8) for _ in range(n))

    @contextmanager
    def field(self, path: str):
        start = self.pos
        yield
        self.spans[path] = (self.base_bit + start, self.base_bit + self.pos)


def bits_for(lo: int, hi: int) -> int:
    return (hi - lo).bit_length()


def put_int(w: BitWriter, v: int, lo: int, hi: int) -> None:
    if not lo <= v <= hi:
        raise ValueError(f"{v} outside ({lo}..{hi})")
    w.put(v - lo, bits_for(lo, hi))


def get_int(r: BitReader, lo: int, hi: int) -> int:
    v = r.get(bits_for(lo, hi)) + lo
    if v > hi:
        raise PerDecodeError(f"value {v} outside ({lo}..{hi})")
    return v


def put_length(w: BitWriter, n: int) -> None:
    """Unconstrained length determinant (n < 16384)."""
    if n < 128:
        w.put(n, 8)
    elif n < 16384:
        w.put(0x8000 | n, 16)
    else:
        raise ValueError("fragmented lengths are not needed by the test system")


def get_length(r: BitReader) -> int:
    if r.get(1) == 0:
        return r.get(7)
    if r.get(1) == 0:
        return r.get(14)
    raise PerDecodeError("fragmented length not supported")


def put_octets(w: BitWriter, data: bytes) -> None:
    put_length(w, len(data))
    w.put_bytes(data)


def get_octets(r: BitReader) -> bytes:
    return r.get_bytes(get_length(r))


def get_normally_small_length(r: BitReader) -> int:
    if r.get(1) == 0:
        return r.get(6) + 1
    return get_length(r)


def skip_extension_additions(r: BitReader) -> None:
    """Skips the extension additions of an extensible SEQUENCE (each is an open type)."""
    n = get_normally_small_length(r)
    present = [r.get(1) for _ in range(n)]
    for p in present:
        if p:
            get_octets(r)
