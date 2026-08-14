import base64
import os
from Crypto.Cipher import AES  # nosec B413


class AuthenticatedEncryption:
    """Implements AES-256-GCM (AEAD) encryption and decryption to prevent
    padding oracle side-channel attacks and ciphertext tampering.
    """

    def __init__(self, key: bytes = None):
        self.key = key or os.urandom(32)
        if len(self.key) != 32:
            raise ValueError("Key must be exactly 32 bytes (256 bits).")

    def encrypt(self, plaintext: bytes | str, associated_data: bytes = None) -> str:
        """Encrypts plaintext using AES-256-GCM.
        Returns base64 string containing: 12-byte nonce + 16-byte auth tag + ciphertext.
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        nonce = os.urandom(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)

        if associated_data:
            cipher.update(associated_data)

        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        payload = nonce + tag + ciphertext
        return base64.b64encode(payload).decode("utf-8")

    def decrypt(self, encoded_payload: str, associated_data: bytes = None) -> bytes:
        """Decrypts base64 payload and validates authentication tag.
        Raises ValueError if tampering is detected.
        """
        raw_payload = base64.b64decode(encoded_payload.encode("utf-8"))
        if len(raw_payload) < 28:
            raise ValueError("Invalid payload: shorter than minimum nonce + tag length.")

        nonce = raw_payload[:12]
        tag = raw_payload[12:28]
        ciphertext = raw_payload[28:]

        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        if associated_data:
            cipher.update(associated_data)

        return cipher.decrypt_and_verify(ciphertext, tag)


if __name__ == "__main__":
    cipher = AuthenticatedEncryption()
    encrypted = cipher.encrypt("Sentinel Payload Security Active", associated_data=b"auth_context")
    decrypted = cipher.decrypt(encrypted, associated_data=b"auth_context")

    print(f"[+] Saved to aead_crypto.py")
    print(f"[+] Self-Test Decrypted Result: {decrypted.decode('utf-8')}")
