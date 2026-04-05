
import sqlite3
import os

# Database path
db_path = os.path.join(os.getcwd(), 'instance', 'ids.db')

def migrate():
    if not os.path.exists(db_path):
        print("[-] Database not found. Skipping Topology migration.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("[*] Hardening Database with Topology Discovery Fields (Phase 7)...")

    try:
        # Add destination fields to threat_log
        cursor.execute("ALTER TABLE threat_log ADD COLUMN destination_ip TEXT DEFAULT '127.0.0.1';")
        cursor.execute("ALTER TABLE threat_log ADD COLUMN destination_port INTEGER DEFAULT 0;")
        print("[+] SUCCESS: Added 'destination_ip' and 'destination_port' to threat_log.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("[!] Topology columns already exist inside the secure enclave.")
        else:
            print(f"[-] ERROR Migrating Topology: {e}")

    conn.commit()
    conn.close()
    print("[*] Topology Schema Synchronized.")

if __name__ == "__main__":
    migrate()
