import base64
import unittest
from hybrid_crypto import HybridEncryption


class TestHybridEncryption(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv_key, cls.pub_key = HybridEncryption.generate_key_pair(bits=2048)
        cls.sender = HybridEncryption(public_key_pem=cls.pub_key)
        cls.receiver = HybridEncryption(private_key_pem=cls.priv_key)
        cls.sample_payload = "Sentinel Telemetry Unit Test"
        cls.context = b"agent_v1_telemetry"

    def test_hybrid_encrypt_decrypt(self):
        encrypted = self.sender.encrypt(self.sample_payload, associated_data=self.context)
        decrypted = self.receiver.decrypt(encrypted, associated_data=self.context)
        self.assertEqual(decrypted.decode("utf-8"), self.sample_payload)

    def test_ciphertext_tampering_rejected(self):
        encrypted = self.sender.encrypt(self.sample_payload, associated_data=self.context)
        raw = bytearray(base64.b64decode(encrypted))
        raw[-1] ^= 0xFF
        tampered = base64.b64encode(raw).decode("utf-8")

        with self.assertRaises(ValueError):
            self.receiver.decrypt(tampered, associated_data=self.context)

    def test_mismatched_context_rejected(self):
        encrypted = self.sender.encrypt(self.sample_payload, associated_data=self.context)
        with self.assertRaises(ValueError):
            self.receiver.decrypt(encrypted, associated_data=b"wrong_context")

    def test_missing_private_key_raises_error(self):
        encrypted = self.sender.encrypt(self.sample_payload)
        with self.assertRaises(ValueError):
            self.sender.decrypt(encrypted)


if __name__ == "__main__":
    unittest.main()
