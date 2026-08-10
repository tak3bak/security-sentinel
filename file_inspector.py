import os
from typing import Dict, Any

class FileInspector:
    """Inspects file metadata and attributes for security monitoring."""

    def __init__(self, file_path: str):
        self.file_path = os.path.abspath(file_path)

    def inspect(self) -> Dict[str, Any]:
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Target file not found: {self.file_path}")

        stat = os.stat(self.file_path)
        return {
            "path": self.file_path,
            "size_bytes": stat.st_size,
            "permissions": oct(stat.st_mode)[-3:],
            "is_file": os.path.isfile(self.file_path),
            "is_dir": os.path.isdir(self.file_path),
        }
