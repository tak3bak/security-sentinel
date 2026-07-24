import os
from cryptography.fernet import Fernet

class VaultManager:
    def __init__(self, vault_path="data/secure.vault", key_path="data/secret.key"):
        self.vault_path = vault_path
        self.key_path = key_path
        self._init_keys()

    def _init_keys(self):
        os.makedirs(os.path.dirname(self.vault_path), exist_ok=True)
        if not os.path.exists(self.key_path):
            key = Fernet.generate_key()
            with open(self.key_path, "wb") as f:
                f.write(key)

    def _get_cipher(self):
        with open(self.key_path, "rb") as f:
            key = f.read()
        return Fernet(key)

    def encrypt_secret(self, secret_name, plaintext_secret):
        cipher = self._get_cipher()
        encrypted_data = cipher.encrypt(plaintext_secret.encode())
        
        vault = {}
        if os.path.exists(self.vault_path):
            try:
                import json
                with open(self.vault_path, "r") as f:
                    vault = json.load(f)
            except Exception:
                vault = {}
                
        vault[secret_name] = encrypted_data.decode()
        
        import json
        with open(self.vault_path, "w") as f:
            json.dump(vault, f)
        print(f"[+] Securely stored '{secret_name}' into encrypted vault storage configuration.")
import os
from cryptography.fernet import Fernet

class VaultManager:
    def __init__(self, vault_path="data/secure.vault", key_path="data/secret.key"):
        self.vault_path = vault_path
        self.key_path = key_path
        self._init_keys()

    def _init_keys(self):
        os.makedirs(os.path.dirname(self.vault_path), exist_ok=True)
        if not os.path.exists(self.key_path):
            key = Fernet.generate_key()
            with open(self.key_path, "wb") as f:
                f.write(key)

    def _get_cipher(self):
        with open(self.key_path, "rb") as f:
            key = f.read()
        return Fernet(key)

    def encrypt_secret(self, secret_name, plaintext_secret):
        cipher = self._get_cipher()
        encrypted_data = cipher.encrypt(plaintext_secret.encode())
        
        vault = {}
        if os.path.exists(self.vault_path):
            try:
                import json
                with open(self.vault_path, "r") as f:
                    vault = json.load(f)
            except Exception:
                vault = {}
                
        vault[secret_name] = encrypted_data.decode()
        
        import json
        with open(self.vault_path, "w") as f:
            json.dump(vault, f)
        print(f"[+] Securely stored '{secret_name}' into encrypted vault storage configuration.")
