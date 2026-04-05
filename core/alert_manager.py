import requests
import os
import json
import threading

def send_webhook_alert(message, webhook_url):
    """Generic helper to send JSON payloads to any compatible webhook."""
    if not webhook_url:
        return
    
    try:
        payload = {"text": message}
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception as e:
        print(f"[-] Webhook Alert Failure: {e}")

def notify_incident_async(label, source_ip, confidence, flow_id, reasoning=""):
    """
    Dispatches alerts to all configured channels asynchronously 
    to avoid blocking the main inference loop.
    """
    slack_url = os.getenv('SLACK_WEBHOOK_URL')
    discord_url = os.getenv('DISCORD_WEBHOOK_URL')
    
    if not slack_url and not discord_url:
        return

    # Advanced SOC Notification Payload
    alert_text = (
        f"🚨 *CRITICAL THREAT DETECTED*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"*Attack Type:* `{label}`\n"
        f"*Source IP:* `{source_ip}`\n"
        f"*Confidence:* `{confidence*100:.2f}%`\n"
        f"*Flow ID:* `{flow_id}`\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"*Forensic Reasoning:* _{reasoning or 'Real-time signature match.'}_"
    )

    # Dispatch to Slack
    if slack_url:
        threading.Thread(target=send_webhook_alert, args=(alert_text, slack_url), daemon=True).start()

    # Dispatch to Discord (supports same JSON 'text' field via simple bridge or direct hook)
    if discord_url:
        threading.Thread(target=send_webhook_alert, args=(alert_text, discord_url), daemon=True).start()
