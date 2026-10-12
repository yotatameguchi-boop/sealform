"""sealform のサーバー側検証（Python）。

ブラウザから届いた値が sealform の暗号文の形をしているかを確かめる。復号はしない
（サーバーは秘密鍵を持たない）。平文が混ざって届いたときに保存を拒否するために使う。
判定は Node 版の isSealed / isSealedFile と同じ（test-vectors/validator.json で確認）。
"""
import base64
import binascii
import json
import re

__all__ = ["is_sealed", "is_sealed_file"]

_SF1 = re.compile(r"sf1\.[0-9a-f]{16}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_SF2 = re.compile(r"sf2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_SF2_HEAD = re.compile(r"sf2\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)")
_RECIPIENT_BYTES = 8 + 1120 + 48
_MAX_RECIPIENTS = 10
_MAX_HEAD = 64 * 1024


def is_sealed(value) -> bool:
    """文字列の値が暗号文（sf1 / sf2）の形をしているか。"""
    return isinstance(value, str) and bool(_SF2.fullmatch(value) or _SF1.fullmatch(value))


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def is_sealed_file(data: bytes) -> bool:
    """受け取ったファイルの中身が、sealform で暗号化したファイル（sf2f）か。"""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 8 or data[:4] != b"sf2f":
        return False
    head_len = int.from_bytes(data[4:8], "big")
    if head_len > _MAX_HEAD or 8 + head_len > len(data):
        return False
    try:
        head = data[8 : 8 + head_len].decode("utf-8")
    except UnicodeDecodeError:
        return False
    m = _SF2_HEAD.fullmatch(head)
    if not m:
        return False
    try:
        meta = json.loads(_b64url(m.group(1)).decode("utf-8"))
        rcpt = _b64url(m.group(2))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return False
    if not isinstance(meta, dict) or meta.get("v") != 2 or meta.get("k") not in ("text", "file"):
        return False
    if not isinstance(meta.get("f"), str) or not isinstance(meta.get("n"), str):
        return False
    if not isinstance(meta.get("t"), (int, float)) or isinstance(meta.get("t"), bool):
        return False
    n = len(rcpt)
    return n > 0 and n % _RECIPIENT_BYTES == 0 and n // _RECIPIENT_BYTES <= _MAX_RECIPIENTS
