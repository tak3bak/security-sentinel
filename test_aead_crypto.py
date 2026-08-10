import base64
import unittest
from aead_crypto import AuthenticatedEncryption


class TestAuthenticatedEncryption(unittest.TestCase):

    def setUp(self):
        self.crypto = AuthenticatedEncryption()
        self.sample_data = "Sentinel System Diagnostic: OK"
        self.context = b"sentinel_v1_telemetry"

    def test_successful_encryption_decryption(self):
        """Verify normal encrypt/decrypt cycle."""
        encrypted = self.crypto.encrypt(self.sample_data, associated_data=self.context)
        decrypted = self.crypto.decrypt(encrypted, associated_data=self.context)
        self.assertEqual(decrypted.decode("utf-8"), self.sample_data)

    def test_ciphertext_tampering_fails(self):
        """Ensure bit-flipping in ciphertext is caught before decryption."""
        encrypted = self.crypto.encrypt(self.sample_data, associated_data=self.context)
        raw_bytes = bytearray(base64.b64decode(encrypted))
        
        # Corrupt ciphertext byte
        raw_bytes[-1] ^= 0xFF
        tampered_payload = base64.b64encode(raw_bytes).decode("utf-8")

        with self.assertRaises(ValueError):
            self.crypto.decrypt(tampered_payload, associated_data=self.context)

    def test_aad_mismatch_fails(self):
        """Ensure payload decrypted under incorrect context is rejected."""
        encrypted = self.crypto.encrypt(self.sample_data, associated_data=self.context)
        
        with self.assertRaises(ValueError):
            self.crypto.decrypt(encrypted, associated_data=b"invalid_context")

    def test_invalid_key_length(self):
        """Verify key length enforcement."""
        with self.assertRaises(ValueError):
            AuthenticatedEncryption(key=b"short_key")


if __name__ == "__main__":
    unittest.main()
