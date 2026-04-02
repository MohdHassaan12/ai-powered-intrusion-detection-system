import os
import subprocess
import json

CONFIG_FILE = 'config.json'
BANNED_IPS_FILE = 'data/logs/banned_ips.txt'

def load_settings():
    if not os.path.exists(CONFIG_FILE):
        return {}
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def is_ip_banned(ip):
    if not os.path.exists(BANNED_IPS_FILE):
        return False
    with open(BANNED_IPS_FILE, 'r') as f:
        return ip in f.read()

def auto_ban_ip(source_ip):
    """
    Checks if active block is enabled via config.
    If so, records the IP and dynamically updates the macOS `pf` firewall.
    """
    config = load_settings()
    
    # Check if admin turned on the IPS capability
    if not config.get('active_block', False):
        return False
        
    if is_ip_banned(source_ip):
        return False # Already banned

    print(f"[!] ACTIVE MITIGATION: Banning hostile IP {source_ip} via pfctl...")

    # Log to flat file
    with open(BANNED_IPS_FILE, 'a') as f:
        f.write(source_ip + "\n")

    # Only works if running as root!
    if os.geteuid() == 0:
        try:
            # We add a quick block rule to block all incoming from the hostile IP
            rule = f"block drop in quick from {source_ip} to any\n"
            
            # Appending to pf config involves reloading the ruleset. 
            # In a true prod env, we map this to a specific anchor.
            subprocess.run(f"echo '{rule}' | pfctl -a com.apple/ai_ids -f -", shell=True)
            return True
        except Exception as e:
            print(f"[-] Auto-ban firewall error: {e}")
            return False
    else:
        print("[-] Cannot apply IP ban because application is NOT running natively as root (sudo).")
        return False
