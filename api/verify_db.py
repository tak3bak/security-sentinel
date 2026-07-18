#!/usr/bin/env python3
import sqlite3

DB_PATH = "sentinel_leases.db"

def print_leases():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if table exists first
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='leases'")
        if not cursor.fetchone():
            print("❌ The 'leases' table does not exist yet. Make sure the Flask app has run at least once.")
            conn.close()
            return
            
        cursor.execute("SELECT id, customer_email, stripe_customer_id, tier, status, updated_at FROM leases")
        rows = cursor.fetchall()
        
        if not rows:
            print("📭 Database is empty. Go trigger a stripe checkout event first!")
            conn.close()
            return

        print("\n=== CURRENT ACTIVE LEASES ===")
        print(f"{'ID':<4} | {'Email':<30} | {'Customer ID':<20} | {'Tier':<10} | {'Status':<10} | {'Updated At'}")
        print("-" * 105)
        for row in rows:
            print(f"{row[0]:<4} | {str(row[1]):<30} | {str(row[2]):<20} | {str(row[3]):<10} | {str(row[4]):<10} | {row[5]}")
        print("=============================\n")
        
        conn.close()
    except Exception as e:
        print(f"❌ Error reading database: {e}")

if __name__ == "__main__":
    print_leases()
