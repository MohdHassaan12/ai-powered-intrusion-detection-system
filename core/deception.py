
import socket
import threading
import time
from datetime import datetime
from core import firewall_ops

# Shared state for deception log queue (to be processed by app context)
deception_queue = []

def honey_port_listener(app, db, DeceptionLog, FirewallRule, Settings, port):
    """
    Listens on a decoy port and triggers an immediate IPS ban for any connection.
    This provides a zero-false-positive detection layer.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('0.0.0.0', port))
        server.listen(5)
        print(f"[*] DECEPTION LAYER: Honey-Port {port} active and lured.")
        
        while True:
            client, addr = server.accept()
            src_ip = addr[0]
            
            # 1. Capture payload (up to 1KB)
            payload = ""
            try:
                client.settimeout(1.0)
                payload = client.recv(1024).decode('utf-8', errors='ignore')
            except: pass
            
            print(f"[!] DECEPTION HIT: IP {src_ip} trapped on Honey-Port {port}!")
            
            with app.app_context():
                # 2. Check Auto-Pilot for immediate mitigation
                setting = Settings.query.first()
                was_banned = False
                if setting and setting.auto_pilot:
                    firewall_ops.auto_ban_ip(src_ip)
                    new_rule = FirewallRule(
                        ip_address=src_ip, 
                        reason=f"Honey-Net Trip: Port {port}", 
                        ban_mode='auto-pilot'
                    )
                    db.session.add(new_rule)
                    was_banned = True
                
                # 3. Persistent Deception Log
                new_hit = DeceptionLog(
                    ip_address=src_ip,
                    port=port,
                    payload=payload if payload else "Handshake Only",
                    ban_status=was_banned
                )
                db.session.add(new_hit)
                db.session.commit()

            client.close()
    except Exception as e:
        print(f"[-] DECEPTION ERROR on Port {port}: {e}")
    finally:
        server.close()

def start_deception_layer(app, db, DeceptionLog, FirewallRule, Settings, ports=[22, 23, 3306, 8080]):
    """Spawns listeners for all decoy ports in specialized threads."""
    for port in ports:
        t = threading.Thread(
            target=honey_port_listener, 
            args=(app, db, DeceptionLog, FirewallRule, Settings, port),
            daemon=True
        )
        t.start()
