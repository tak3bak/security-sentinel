import sqlite3
import time

DB_PATH = "sentinel_leases.db"

def get_db_connection():
    """Shared database connection pattern."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def run_event_loop():
    print("Event loop initialized and synced with SQLite.")
    while True:
        try:
            conn = get_db_connection()
            # Example: Check for pending security tasks
            # This logic now reads from the same DB used by your Stripe webhooks
            cursor = conn.execute("SELECT * FROM leases WHERE status = 'active'")
            active_users = cursor.fetchall()
            
            # Add your monitoring logic here
            # print(f"Processing {len(active_users)} active leases...")
            
            conn.close()
        except Exception as e:
            print(f"Error in event loop: {e}")
            
        time.sleep(30) # Adjust poll interval as needed

if __name__ == "__main__":
    run_event_loop()
