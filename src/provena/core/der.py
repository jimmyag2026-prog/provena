"""Minimal ASN.1 DER reader/writer — just enough for RFC 3161 time-stamp tokens.

Kept in core (no extra dependency) because the verifier must parse anchor receipts offline.
"""

from __future__ import annotations

from dataclasses import dataclass

from provena.core.errors import VerificationError

SEQUENCE, SET, INTEGER, OCTET_STRING, OID, NULL, BOOLEAN, GENERALIZED_TIME = (
    0x30, 0x31, 0x02, 0x04, 0x06, 0x05, 0x01, 0x18)


@dataclass(frozen=True)
class Node:
    tag: int
    raw: bytes        # the full TLV encoding
    content: bytes    # the value bytes

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> list[Node]:
        if not self.constructed:
            raise VerificationError(f"DER: tag {self.tag:#x} is primitive")
        out, pos = [], 0
        while pos < len(self.content):
            node, pos = _read(self.content, pos)
            out.append(node)
        return out

    def child(self, i: int) -> Node:
        kids = self.children()
        if i >= len(kids):
            raise VerificationError("DER: missing element")
        return kids[i]


def _read(data: bytes, pos: int) -> tuple[Node, int]:
    if pos + 2 > len(data):
        raise VerificationError("DER: truncated")
    start, tag = pos, data[pos]
    if tag & 0x1F == 0x1F:
        raise VerificationError("DER: high tag numbers unsupported")
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise VerificationError("DER: bad length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise VerificationError("DER: truncated value")
    return Node(tag, data[start:end], data[pos:end]), end


def parse(data: bytes) -> Node:
    node, end = _read(data, 0)
    if end != len(data):
        raise VerificationError("DER: trailing data")
    return node


def as_int(node: Node) -> int:
    if node.tag != INTEGER:
        raise VerificationError("DER: expected INTEGER")
    return int.from_bytes(node.content, "big", signed=True)


def as_oid(node: Node) -> str:
    if node.tag != OID:
        raise VerificationError("DER: expected OID")
    b = node.content
    parts = [b[0] // 40, b[0] % 40] if b[0] < 80 else [2, b[0] - 80]
    value = 0
    for byte in b[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(map(str, parts))


# -- writer -------------------------------------------------------------------------------------

def tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    length = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + content


def seq(*items: bytes) -> bytes:
    return tlv(SEQUENCE, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(SET, b"".join(sorted(items)))


def integer(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return tlv(INTEGER, value.to_bytes(length, "big", signed=True))


def oid(dotted: str) -> bytes:
    nums = [int(x) for x in dotted.split(".")]
    body = bytes([40 * nums[0] + nums[1]])
    for n in nums[2:]:
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        body += bytes(reversed(chunk))
    return tlv(OID, body)


def octets(data: bytes) -> bytes:
    return tlv(OCTET_STRING, data)


def null() -> bytes:
    return tlv(NULL, b"")


def boolean(value: bool) -> bytes:
    return tlv(BOOLEAN, b"\xff" if value else b"\x00")


def explicit(number: int, content: bytes) -> bytes:
    return tlv(0xA0 | number, content)
