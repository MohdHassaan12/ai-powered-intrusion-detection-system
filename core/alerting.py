import json
import requests
import threading
import os

CONFIG_FILE = 'config.json'

def load_settings():
    if not os.path.exists(CONFIG_FILE):
        return {}
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def send_webhook_alert_async(threat_type, source_ip, confidence, flow_id):
    """
    Spawns a background thread to send the webhook so it doesn't block the live monitor loop.
    """
    thread = threading.Thread(
        target=_dispatch_webhook,
        args=(threat_type, source_ip, confidence, flow_id)
    )
    thread.daemon = True
    thread.start()

def _dispatch_webhook(threat_type, source_ip, confidence, flow_id):
    config = load_settings()
    webhook_url = config.get('webhook_url', '')

    if not webhook_url or not webhook_url.startswith('http'):
        return  # No valid webhook configured

    # Discord / Slack compatible payload
    payload = {
        "username": "AI-IDS Command Center",
        "avatar_url": "https://img.icons8.com/color/512/artificial-intelligence.png",
        "embeds": [
            {
                "title": "🚨 HIGH-SEVERITY THREAT DETECTED 🚨",
                "color": 16711680, # Red
                "fields": [
                    {
                        "name": "Threat Classification",
                        "value": f"**{threat_type}**",
                        "inline": True
                    },
                    {
                        "name": "Source IP Address",
                        "value": f"`{source_ip}`",
                        "inline": True
                    },
                    {
                        "name": "AI Confidence",
                        "value": f"{confidence * 100:.2f}%",
                        "inline": True
                    },
                    {
                        "name": "Flow ID",
                        "value": f"`{flow_id}`",
                        "inline": False
                    }
                ],
                "footer": {
                    "text": "Automated AI Security Infrastructure"
                }
            }
        ]
    }

    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception as e:
        print(f"[-] Failed to dispatch webhook: {e}")
