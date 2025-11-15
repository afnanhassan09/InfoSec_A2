"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

import base64
import hashlib
import time

def now_ms():
    return int(time.time() * 1000)


def b64e(b: bytes):
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str):
    return base64.b64decode(s.encode("utf-8"))


def sha256_hex(data: bytes):
    return hashlib.sha256(data).hexdigest()


