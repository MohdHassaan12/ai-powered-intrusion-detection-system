
import sqlite3
import os

# Database path
db_path = os.path.join(os.getcwd(), 'instance', 'ids.db')

def migrate():
    if not os.path.exists(db_path):
        print("[-] Database not found. Skipping OSINT migration.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("[*] Hardening Database with OSINT Reputation Fields...")

    try:
        # Add reputation field to threat_log
        cursor.execute("ALTER TABLE threat_log ADD COLUMN reputation INTEGER DEFAULT 0;")
        print("[+] SUCCESS: Added 'reputation' column to threat_log.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("[!] Column 'reputation' already exists inside the secure enclave.")
        else:
            print(f"[-] ERROR Migrating reputation: {e}")

    conn.commit()
    conn.close()
    print("[*] OSINT Migration Schema Synchronized.")

if __name__ == "__main__":
    migrate()
