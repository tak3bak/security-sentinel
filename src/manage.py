import sys
import os
import shutil
import sqlite3
from pathlib import Path

DB_PATH = Path("sentinel_data/sentinel_vault.db")

def get_db_connection():
    if not DB_PATH.exists():
        print(f"[-] Error: Database not found at {DB_PATH}.")
        sys.exit(1)
    return sqlite3.connect(DB_PATH)

def list_artifacts():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, original_path, file_sha256, detected_at, status FROM quarantined_artifacts;")
    rows = cursor.fetchall()
    conn.close()
    if not rows:
        print("[*] No records found.")
        return
    print("\n" + "="*90)
    print(f"{'ID':<4} | {'STATUS':<12} | {'DETECTED AT':<19} | {'ORIGINAL PATH'}")
    print("="*90)
    for row in rows:
        print(f"{row[0]:<4} | {row[4]:<12} | {row[3]:<19} | {row[1]}")
    print("="*90 + "\n")

def restore_artifact(artifact_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, original_path, quarantine_path, status FROM quarantined_artifacts WHERE id = ?;", (artifact_id,))
    row = cursor.fetchone()
    if not row:
        print(f"[-] Error: No artifact found matching ID {artifact_id}")
        conn.close()
        return
    art_id, original_path_str, quarantine_path_str, status = row
    q_path = Path(quarantine_path_str)
    o_path = Path(original_path_str)
    if not q_path.exists():
        print(f"[-] Critical: Vaulted file missing from storage layer at {q_path}")
        conn.close()
        return
    try:
        print(f"[*] Extracting file from isolation storage...")
        o_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(q_path), str(o_path))
        os.chmod(str(o_path), 0o644)
        cursor.execute("UPDATE quarantined_artifacts SET status = 'RESTORED' WHERE id = ?;", (artifact_id,))
        conn.commit()
        print(f"[+] SUCCESS: Disk asset restored completely to {o_path}")
    except Exception as e:
        print(f"[-] File system transmission failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python manage.py [list | restore <id>]")
        sys.exit(1)
    cmd = sys.argv[1].lower()
    if cmd == "list":
        list_artifacts()
    elif cmd == "restore":
        restore_artifact(int(sys.argv[2]))
