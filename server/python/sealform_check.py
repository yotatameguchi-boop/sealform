"""sealform のサーバー側検証（Python）。

ブラウザから届いた値が sealform の暗号文の形をしているかを確かめる。復号はしない
（サーバーは秘密鍵を持たない）。平文が混ざって届いたときに保存を拒否するために使う。
判定は Node 版の isSealed / isSealedFile と同じ（test-vectors/validator.json で確認）。

注意: 確かめられるのは「形」だけで、暗号文が本物か（改ざんされていないか）は
秘密鍵で復号するときに初めて分かる。
"""
import base64
import binascii
import json
import re

__all__ = ["is_sealed", "is_sealed_file"]

_SF1 = re.compile(r"sf1\.([0-9a-f]{16})\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)")
_SF2 = re.compile(r"sf2\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)")
_SF2_HEAD = re.compile(r"sf2\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)")
_ENC_BYTES = 1120
_RECIPIENT_BYTES = 8 + _ENC_BYTES + 48
_MAX_RECIPIENTS = 10
_MAX_HEAD = 64 * 1024
_TEXT_PAD = 64
_FILE_PAD = 4096


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _meta(part: str, version: int):
    meta = json.loads(_b64url(part).decode("utf-8"))
    if not isinstance(meta, dict) or meta.get("v") != version:
        return None
    if not isinstance(meta.get("f"), str) or not isinstance(meta.get("n"), str):
        return None
    t = meta.get("t")
    if isinstance(t, bool) or not isinstance(t, (int, float)):
        return None
    return meta


def _recipients_ok(part: str) -> bool:
    n = len(_b64url(part))
    return n > 0 and n % _RECIPIENT_BYTES == 0 and n // _RECIPIENT_BYTES <= _MAX_RECIPIENTS


def _body_ok(length: int, bucket: int, iv: int = 12) -> bool:
    ct = length - iv - 16
    return ct >= bucket and ct % bucket == 0


def is_sealed(value) -> bool:
    """文字列の値が暗号文（sf1 / sf2）の形をしているか。"""
    if not isinstance(value, str):
        return False
    try:
        m = _SF2.fullmatch(value)
        if m:
            meta = _meta(m.group(1), 2)
            return (meta is not None and meta.get("k") == "text" and _recipients_ok(m.group(2))
                    and _body_ok(len(_b64url(m.group(3))), _TEXT_PAD))
        m = _SF1.fullmatch(value)
        if m:
            return (_meta(m.group(2), 1) is not None and len(_b64url(m.group(3))) == _ENC_BYTES
                    and _body_ok(len(_b64url(m.group(4))), _TEXT_PAD, iv=0))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return False
    return False


def is_sealed_file(data: bytes) -> bool:
    """受け取ったファイルの中身が、sealform で暗号化したファイル（sf2f）の形をしているか。"""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 8 or data[:4] != b"sf2f":
        return False
    head_len = int.from_bytes(data[4:8], "big")
    if head_len > _MAX_HEAD or 8 + head_len > len(data):
        return False
    try:
        m = _SF2_HEAD.fullmatch(data[8 : 8 + head_len].decode("utf-8"))
        if not m:
            return False
        meta = _meta(m.group(1), 2)
        return (meta is not None and meta.get("k") == "file" and _recipients_ok(m.group(2))
                and _body_ok(len(data) - 8 - head_len, _FILE_PAD))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return False
