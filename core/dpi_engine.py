import yara
import os
import threading
from scapy.all import sniff, IP, TCP, UDP, Raw

# Global singleton for the YARA forensic scanner
FORENSIC_SCANNER = None

def load_forensic_rules():
    """Initializes the YARA forensic scanner with baseline signatures."""
    global FORENSIC_SCANNER
    rule_path = os.path.join("assets", "rules", "forensic_signatures.yar")
    if os.path.exists(rule_path):
        try:
            FORENSIC_SCANNER = yara.compile(filepath=rule_path)
            print("[+] DPI: Forensic YARA rules loaded successfully.")
        except Exception as e:
            print(f"[-] DPI: Forensic YARA compilation error: {e}")
    else:
        print("[-] DPI: Forensic YARA rule file not found. Signature scanning suppressed.")

def scan_payload(payload):
    """
    Performs Deep Packet Inspection (DPI) on a raw binary payload.
    Returns a list of matching forensic signatures.
    """
    if not FORENSIC_SCANNER or not payload:
        return []
        
    try:
        matches = FORENSIC_SCANNER.match(data=payload)
        return [m.rule for m in matches]
    except:
        return []

def background_dpi_sniffer(interface="en0", callback=None):
    """
    Parallel SOC Sniffer: Intercepts raw binary payloads from the network 
    and performs deep content analysis.
    """
    print(f"[+] DPI: Parallel content sniffer active on {interface}.")
    
    def handle_packet(packet):
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            matches = scan_payload(payload)
            if matches and callback:
                src_ip = packet[IP].src if IP in packet else "Unknown"
                callback(src_ip, matches, payload.hex()[:100])

    try:
        sniff(iface=interface, prn=handle_packet, store=0)
    except Exception as e:
        print(f"[-] DPI: Sniffer failure: {e}")

# Initialise forensic core
load_forensic_rules()
