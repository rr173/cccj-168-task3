"""密码学原语：规范 JSON 序列化、内容哈希、HMAC 委员签名。

- canonical_json：键排序、无空白、保留非 ASCII，保证跨端字节一致
- sha256_hex：SHA-256 十六进制
- hmac_hex：HMAC-SHA256（委员私钥对投票载荷签名）
"""
from __future__ import annotations

import hashlib
import hmac
import json


def canonical_json(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(obj) -> str:
    return sha256_hex(canonical_json(obj))


def hmac_hex(secret: str, data: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()


def verify_hmac(secret: str, data: bytes, signature: str) -> bool:
    return hmac.compare_digest(hmac_hex(secret, data), signature or "")
