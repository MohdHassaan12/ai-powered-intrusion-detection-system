import os
import requests
import json
from dotenv import load_dotenv
from functools import lru_cache

load_dotenv()

@lru_cache(maxsize=1024)
def get_abuseipdb_reputation(ip_address):
    """Query AbuseIPDB for IP reputation."""
    if ip_address.startswith(("192.168", "10.", "127.", "172.16")):
        return 0
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key: return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Accept': 'application/json', 'Key': api_key}
    try:
        r = requests.get(url, headers=headers, params={'ipAddress': ip_address}, timeout=3)
        if r.status_code == 200:
            return r.json()['data']['abuseConfidenceScore']
    except: pass
    return 0

def get_vt_reputation(ip_address):
    """Query VirusTotal for malicious IP score."""
    api_key = os.getenv("VT_API_KEY")
    if not api_key: return None
    try:
        from virustotal_python import Virustotal
        v = Virustotal(api_key=api_key)
        r = v.request(f"ip_addresses/{ip_address}")
        stats = r.data['attributes']['last_analysis_stats']
        malicious = stats['malicious']
        total = sum(stats.values())
        return (malicious / total) * 100 if total > 0 else 0
    except: pass
    return 0

def get_otx_reputation(ip_address):
    """Query AlienVault OTX for IP pulses."""
    api_key = os.getenv("OTX_API_KEY")
    if not api_key: return None
    try:
        from OTXv2 import OTXv2
        otx = OTXv2(api_key)
        r = otx.get_indicator_details_full("IPv4", ip_address)
        pulse_count = len(r.get('general', {}).get('pulses', []))
        return min(pulse_count * 10, 100) # 10 pulses = 100% confidence
    except: pass
    return 0

def get_ensemble_reputation(ip_address):
    """Combines multiple OSINT sources into a single Forensic Trust Score."""
    scores = []
    
    a_score = get_abuseipdb_reputation(ip_address)
    if a_score is not None: scores.append(a_score)
    
    v_score = get_vt_reputation(ip_address)
    if v_score is not None: scores.append(v_score)
    
    o_score = get_otx_reputation(ip_address)
    if o_score is not None: scores.append(o_score)
    
    if not scores: return 0
    return sum(scores) / len(scores)
