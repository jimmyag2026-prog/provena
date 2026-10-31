"""Binary <-> text encodings used in signed structures."""

import base64


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b32_lower(data: bytes) -> str:
    return base64.b32encode(data).rstrip(b"=").decode("ascii").lower()
