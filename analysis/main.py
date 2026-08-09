import os
import time
import psycopg2
from dotenv import load_dotenv

load_dotenv()
SPIDERFOOT_API = os.getenv("SPIDERFOOT_API")
DB_URL = "postgresql://sentinel_user:secure_password@sentinel-db:5432/sentinel_db"
raw_keywords = os.getenv("LEAK_KEYWORDS", "")
LEAK_KEYWORDS = [k.strip() for k in raw_keywords.split(",") if k.strip()]


def get_db_connection():
    return psycopg2.connect(DB_URL)


def run_analysis():
    print("Sentinel Analysis Engine Started...")
    while True:
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            print(f"Checking SpiderFoot at {SPIDERFOOT_API}...")

            for keyword in LEAK_KEYWORDS:
                # Logic to parse SpiderFoot results and insert into DB would go here
                cur.execute(
                    "INSERT INTO alerts (keyword_matched, severity) VALUES (%s, %s)",
                    (keyword, "HIGH"),
                )
                conn.commit()
                print(f"Logged alert for: {keyword}")

            cur.close()
            conn.close()
        except Exception as e:
            print(f"Error: {e}")

        time.sleep(60)


if __name__ == "__main__":
    run_analysis()
