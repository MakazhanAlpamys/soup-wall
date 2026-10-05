# SPDX-License-Identifier: Apache-2.0
"""Bounded current-user DPAPI storage for private Windows acceptance artifacts.

Only the Windows logon account can normally decrypt these files. This does not
isolate them from other processes running as that account. No key or plaintext
fallback is stored, and importing this module does not load Windows libraries.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path

MAX_BYTES = 2 * 1024 * 1024
MAX_OVERHEAD = 16384
STORAGE_MAGIC = b"SWDPAPI1\x00"
PAYLOAD_MAGIC = b"SWPAYLOAD1\x00"
PAYLOAD_HEADER = len(PAYLOAD_MAGIC) + 4 + 32


def _dpapi(data: bytes, protect: bool) -> bytes:
    if os.name != "nt":
        raise OSError("native_windows_private_storage_required")
    import ctypes
    from ctypes import wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    crypt32 = ctypes.WinDLL("crypt32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    operation = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    description_type = wintypes.LPCWSTR if protect else ctypes.POINTER(wintypes.LPWSTR)
    operation.argtypes = [ctypes.POINTER(DataBlob), description_type, ctypes.POINTER(DataBlob),
                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DataBlob)]
    operation.restype = wintypes.BOOL
    buffer = ctypes.create_string_buffer(data)
    source = DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output = DataBlob()
    try:
        # UI_FORBIDDEN=1; no LOCAL_MACHINE, description, entropy, reserved or prompt.
        if not operation(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output)):
            raise OSError("private_storage_protect_failed" if protect else "private_storage_unprotect_failed")
        if not output.pbData or not 0 < output.cbData <= MAX_BYTES + MAX_OVERHEAD:
            raise OSError("private_storage_native_output_invalid")
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.memset(buffer, 0, len(buffer))
        if output.pbData:
            # Clear native plaintext buffers before freeing, including failed calls.
            if 0 < output.cbData <= MAX_BYTES + MAX_OVERHEAD:
                ctypes.memset(output.pbData, 0, output.cbData)
            kernel32.LocalFree(ctypes.cast(output.pbData, ctypes.c_void_p))


def _limit(max_bytes):
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_BYTES:
        raise OSError("private_storage_limit_invalid")


def protect_bytes(data: bytes, max_bytes=MAX_BYTES) -> bytes:
    _limit(max_bytes)
    if not isinstance(data, bytes) or len(data) > max_bytes:
        raise OSError("private_storage_plaintext_over_cap")
    payload = PAYLOAD_MAGIC + len(data).to_bytes(4, "big") + hashlib.sha256(data).digest() + data
    encrypted = _dpapi(payload, True)
    if not encrypted or len(encrypted) > max_bytes + MAX_OVERHEAD:
        raise OSError("private_storage_ciphertext_over_cap")
    return STORAGE_MAGIC + encrypted


def unprotect_bytes(data: bytes, max_bytes=MAX_BYTES) -> bytes:
    _limit(max_bytes)
    if (not isinstance(data, bytes) or not data.startswith(STORAGE_MAGIC)
            or not len(STORAGE_MAGIC) < len(data) <= max_bytes + MAX_OVERHEAD + len(STORAGE_MAGIC)):
        raise OSError("private_storage_ciphertext_invalid")
    payload = _dpapi(data[len(STORAGE_MAGIC):], False)
    if not PAYLOAD_HEADER <= len(payload) <= max_bytes + PAYLOAD_HEADER or not payload.startswith(PAYLOAD_MAGIC):
        raise OSError("private_storage_payload_invalid")
    offset = len(PAYLOAD_MAGIC)
    length = int.from_bytes(payload[offset:offset + 4], "big")
    expected = payload[offset + 4:PAYLOAD_HEADER]
    original = payload[PAYLOAD_HEADER:]
    if length != len(original) or length > max_bytes or not hmac.compare_digest(expected, hashlib.sha256(original).digest()):
        raise OSError("private_storage_payload_integrity_failed")
    return original


def write_private(path: Path, data: bytes, max_bytes=MAX_BYTES) -> str:
    encrypted = protect_bytes(data, max_bytes)
    with path.open("xb") as stream:
        stream.write(encrypted)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(encrypted).hexdigest()


def read_private(path: Path, max_bytes=MAX_BYTES) -> bytes:
    _limit(max_bytes)
    with path.open("rb") as stream:
        encrypted = stream.read(max_bytes + MAX_OVERHEAD + len(STORAGE_MAGIC) + 1)
    return unprotect_bytes(encrypted, max_bytes)
