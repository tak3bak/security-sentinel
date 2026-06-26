import os
import shutil

class Remediator:
    def __init__(self, quarantine_dir):
        self.quarantine_dir = quarantine_dir
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

    def quarantine_file(self, file_path):
        """Moves a leaked file to a safe, restricted directory."""
        if os.path.exists(file_path):
            try:
                file_name = os.path.basename(file_path)
                dest = os.path.join(self.quarantine_dir, f"{file_name}.quarantined")
                shutil.move(file_path, dest)
                return True
            except Exception as e:
                print(f"[!] Remediation Error (Quarantine): {e}")
                return False
        return False

    def fix_permissions(self, file_path):
        """Sets file permissions to 644 (Owner: Read/Write, Group: Read, Others: Read)."""
        try:
            os.chmod(file_path, 0o644)
            return True
        except Exception as e:
            print(f"[!] Remediation Error (Permissions): {e}")
            return False