import os
import shutil
import uuid
from pathlib import Path

def quarantine_file(source_path: str, quarantine_dir: str = "./quarantine") -> str:
    """Safely isolates a target file without overwriting existing entries."""
    q_path = Path(quarantine_dir).resolve()
    q_path.mkdir(parents=True, exist_ok=True)

    src = Path(source_path).resolve()
    if not src.is_file():
        raise FileNotFoundError(f"Source file invalid or not found: {source_path}")

    # Append unique suffix to prevent collisions
    unique_name = f"{src.stem}_{uuid.uuid4().hex[:8]}{src.suffix}"
    dest = q_path / unique_name

    shutil.move(str(src), str(dest))
    os.chmod(str(dest), 0o400)  # Read-only isolation
    return str(dest)
