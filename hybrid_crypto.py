import base64
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES


class HybridEncryption:
    """Implements RSA-4096 + AES-256-GCM Hybrid Encryption.
    Public Key encrypts an ephemeral AES key per message.
    Private Key decrypts the ephemeral AES key and validates the payload MAC.
    """

    @staticmethod
    def generate_key_pair(bits: int = 2048) -> tuple[bytes, bytes]:
        """Generates an RSA key pair returning (private_pem, public_pem)."""
        key = RSA.generate(bits)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    def __init__(self, private_key_pem: bytes = None, public_key_pem: bytes = None):
        self.private_key = RSA.import_key(private_key_pem) if private_key_pem else None
        self.public_key = RSA.import_key(public_key_pem) if public_key_pem else None

    def encrypt(self, plaintext: bytes | str, associated_data: bytes = None) -> str:
        """Encrypts payload using an ephemeral AES-256-GCM key wrapped with RSA-OAEP."""
        if not self.public_key:
            raise ValueError("Public key is required for encryption.")

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        # 1. Generate ephemeral 256-bit AES key and 96-bit GCM nonce
        ephemeral_aes_key = os.urandom(32)
        nonce = os.urandom(12)

        # 2. Encrypt plaintext with ephemeral AES-GCM key
        aes_cipher = AES.new(ephemeral_aes_key, AES.MODE_GCM, nonce=nonce)
        if associated_data:
            aes_cipher.update(associated_data)
        ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)

        # 3. Encrypt ephemeral AES key with RSA Public Key (OAEP SHA-256)
        rsa_cipher = PKCS1_OAEP.new(self.public_key)
        wrapped_aes_key = rsa_cipher.encrypt(ephemeral_aes_key)

        # Pack payload: key_len (2B) + wrapped_key + nonce (12B) + tag (16B) + ciphertext
        key_len = len(wrapped_aes_key).to_bytes(2, byteorder="big")
        payload = key_len + wrapped_aes_key + nonce + tag + ciphertext
        return base64.b64encode(payload).decode("utf-8")

    def decrypt(self, encoded_payload: str, associated_data: bytes = None) -> bytes:
        """Unwraps ephemeral AES key via RSA Private Key and decrypts payload."""
        if not self.private_key:
            raise ValueError("Private key is required for decryption.")

        raw_payload = base64.b64decode(encoded_payload.encode("utf-8"))
        if len(raw_payload) < 2:
            raise ValueError("Invalid hybrid payload length.")

        # Extract components from payload
        key_len = int.from_bytes(raw_payload[:2], byteorder="big")
        offset = 2 + key_len

        wrapped_aes_key = raw_payload[2:offset]
        nonce = raw_payload[offset : offset + 12]
        tag = raw_payload[offset + 12 : offset + 28]
        ciphertext = raw_payload[offset + 28 :]

        # 1. Unwrap ephemeral AES key with RSA Private Key
        rsa_cipher = PKCS1_OAEP.new(self.private_key)
        ephemeral_aes_key = rsa_cipher.decrypt(wrapped_aes_key)

        # 2. Decrypt ciphertext and verify MAC tag
        aes_cipher = AES.new(ephemeral_aes_key, AES.MODE_GCM, nonce=nonce)
        if associated_data:
            aes_cipher.update(associated_data)

        return aes_cipher.decrypt_and_verify(ciphertext, tag)


if __name__ == "__main__":
    print("[*] Generating RSA-2048 keypair for test...")
    priv_pem, pub_pem = HybridEncryption.generate_key_pair(bits=2048)

    sender = HybridEncryption(public_key_pem=pub_pem)
    receiver = HybridEncryption(private_key_pem=priv_pem)

    payload = "Sentinel Asymmetric Pipeline Active"
    context = b"hybrid_v1_telemetry"

    print("[*] Encrypting with Public Key...")
    encrypted = sender.encrypt(payload, associated_data=context)
    print(f"[+] Encrypted Payload: {encrypted[:60]}...")

    print("[*] Decrypting with Private Key...")
    decrypted = receiver.decrypt(encrypted, associated_data=context)
    print(f"[+] Decrypted Result: {decrypted.decode('utf-8')}")
