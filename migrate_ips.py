
import os
import sqlite3

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'instance', 'ids.db')

def update_db():
    print(f"[*] Updating database schema at {db_path}...")
    if not os.path.exists(db_path):
        print(f"[!] Database file not found at {db_path}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Add auto_pilot to settings if not exists
    try:
        cursor.execute("ALTER TABLE settings ADD COLUMN auto_pilot BOOLEAN DEFAULT 0")
        print("[+] Added 'auto_pilot' to 'settings' table.")
    except sqlite3.OperationalError:
        print("[!] 'auto_pilot' column likely already exists.")

    # Create firewall_rule table
    try:
        cursor.execute('''
            CREATE TABLE firewall_rule (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address VARCHAR(50) UNIQUE NOT NULL,
                timestamp DATETIME,
                status VARCHAR(20) DEFAULT 'active',
                reason VARCHAR(255),
                ban_mode VARCHAR(20)
            )
        ''')
        print("[+] Created 'firewall_rule' table.")
    except sqlite3.OperationalError as e:
        print(f"[!] 'firewall_rule' table creation issue: {e}")
        
    conn.commit()
    conn.close()
    print("[*] DB Migration complete.")

if __name__ == "__main__":
    update_db()
