"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""
import time

def now_ms():
    return int(time.time() * 1000)

def b64e(b: bytes): raise NotImplementedError

def b64d(s: str): raise NotImplementedError

def sha256_hex(data: bytes): raise NotImplementedError
