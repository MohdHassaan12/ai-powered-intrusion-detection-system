import os
import subprocess
import platform

def auto_ban_ip(source_ip):
    """
    Automated Defensive Response: Bans a malicious IP using system firewall utilities.
    Checks for OS compatibility (Linux/iptables vs. Mac/Mock).
    """
    if not source_ip or source_ip == "127.0.0.1":
        return "Ignored (Local/Invalid IP)"

    system_os = platform.system().lower()
    
    if system_os == "linux":
        try:
            # Check if running as root
            if os.geteuid() != 0:
                return "Permission Denied (Sudo required for IPS)"
            
            # Using iptables to drop all traffic from the source IP
            cmd = ["iptables", "-A", "INPUT", "-s", source_ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            print(f"[!] IPS ACTION: Banned {source_ip} via iptables.")
            return f"Banned {source_ip} (Linux/iptables)"
        except Exception as e:
            return f"IPS Error: {e}"
            
    elif system_os == "darwin": # Mac
        # Mac uses pfctl, but we'll mock it for safety unless explicitly asked
        print(f"[*] IPS SIMULATION: Would ban {source_ip} on Mac (pfctl logic).")
        return f"Simulated Ban: {source_ip}"
    
    else:
        return f"Unsupported OS: {system_os}"

def unban_ip(source_ip):
    """Removes a previously enforced IP ban."""
    system_os = platform.system().lower()
    if system_os == "linux":
        try:
            cmd = ["iptables", "-D", "INPUT", "-s", source_ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            return f"Unbanned {source_ip}"
        except:
            return "Unban failed (IP not in list?)"
    return f"Simulated Unban: {source_ip}"
