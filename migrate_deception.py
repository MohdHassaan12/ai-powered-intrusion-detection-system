
import sqlite3
import os

# Database path
db_path = os.path.join(os.getcwd(), 'instance', 'ids.db')

def migrate():
    if not os.path.exists(db_path):
        print("[-] Database not found. Skipping Deception migration.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("[*] Deploying Deception Layer Schema (Phase 6)...")

    try:
        # Create deception_log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS deception_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                port INTEGER,
                payload TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                ban_status BOOLEAN DEFAULT 0
            );
        ''')
        print("[+] SUCCESS: DeceptionLog table initialized.")
    except sqlite3.OperationalError as e:
        print(f"[-] ERROR Migrating Deception: {e}")

    conn.commit()
    conn.close()
    print("[*] Deception Schema Synchronized.")

if __name__ == "__main__":
    migrate()
