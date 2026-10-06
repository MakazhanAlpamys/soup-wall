# SPDX-License-Identifier: Apache-2.0
"""Native encryption and portable bounds for retained Windows fixture artifacts."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "fixtures/windows_private_storage.py"


def module(test):
    test.assertTrue(SOURCE.is_file(), "Private fixture artifacts require encryption at rest")
    spec = importlib.util.spec_from_file_location("windows_private_storage_under_test", SOURCE)
    storage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(storage)
    return storage


class WindowsPrivateStorage(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Native Windows DPAPI current-user protection")
    def test_encrypts_original_bytes_and_rejects_ciphertext_damage(self):
        storage = module(self)
        with tempfile.TemporaryDirectory() as temporary:
            document = Path(temporary) / "document.private.dpapi"
            original = b"Project: Orchard\nSham credential: AKIAABCDEFGHIJKLMNOP\n"
            stored_hash = storage.write_private(document, original)
            ciphertext = document.read_bytes()
            self.assertNotIn(b"AKIAABCDEFGHIJKLMNOP", ciphertext)
            self.assertNotIn(b"Project: Orchard", ciphertext)
            self.assertEqual(stored_hash, hashlib.sha256(ciphertext).hexdigest())
            self.assertNotEqual(stored_hash, hashlib.sha256(original).hexdigest())
            self.assertEqual(storage.read_private(document), original)
            damaged = bytearray(ciphertext)
            damaged[-16] ^= 1
            document.write_bytes(damaged)
            with self.assertRaises(OSError):
                storage.read_private(document)

    def test_rejects_invalid_decrypted_payload_even_if_os_reports_success(self):
        storage = module(self)
        original = b"assigned document"
        payload = storage.PAYLOAD_MAGIC + len(original).to_bytes(4, "big") + hashlib.sha256(original).digest() + original
        encrypted = storage.STORAGE_MAGIC + b"opaque-ciphertext"
        with patch.object(storage, "_dpapi", return_value=payload):
            self.assertEqual(storage.unprotect_bytes(encrypted), original)
        for corrupt in [payload[:-1] + b"X", payload[:-1], payload + b"X", b"unknown-format"]:
            with patch.object(storage, "_dpapi", return_value=corrupt):
                with self.assertRaises(OSError):
                    storage.unprotect_bytes(encrypted)
        with patch.object(storage, "_dpapi", return_value=payload):
            with self.assertRaises(OSError):
                storage.unprotect_bytes(encrypted, max_bytes=4)

    def test_has_no_plaintext_fallback_or_unbounded_native_call(self):
        storage = module(self)
        with patch.object(storage, "_dpapi", side_effect=AssertionError("native call must not receive invalid input")):
            for invalid in [b"plaintext fixture", storage.STORAGE_MAGIC, storage.STORAGE_MAGIC + b"x" * 20000]:
                with self.assertRaises(OSError):
                    storage.unprotect_bytes(invalid, max_bytes=4)
            with self.assertRaises(OSError):
                storage.protect_bytes(b"too long", max_bytes=4)
        with patch.object(storage.os, "name", "posix"):
            with self.assertRaises(OSError):
                storage.protect_bytes(b"bounded")


if __name__ == "__main__":
    unittest.main()
