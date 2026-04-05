
import requests
import json
from datetime import datetime

def dispatch_alert(threat_data, webhook_url):
    """
    Dispatches a real-time JSON alert to an external webhook (Slack, Discord, or Custom).
    """
    if not webhook_url:
        return False

    # Format the payload for enterprise ingestion
    payload = {
        "text": f"🚨 *Phase 9: Real-time Threat Alert (SOC)*",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "CRITICAL THREAT DETECTED",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Source IP:*\n{threat_data.get('source_ip')}"},
                    {"type": "mrkdwn", "text": f"*Classification:*\n{threat_data.get('label')}"}
                ]
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Neural Confidence:*\n{threat_data.get('confidence')}%"},
                    {"type": "mrkdwn", "text": f"*Timestamp:*\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}
                ]
            },
            {
                "type": "divider"
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "🛡️ *AdvancedIDS SOC Hub* | Phase 9: Real-time Alerting Active"}
                ]
            }
        ]
    }

    try:
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=5
        )
        return response.status_code == 200
    except Exception:
        return False

def format_simulated_alert(source_ip, label, confidence):
    """
    Helper to test alerting with simulated data.
    """
    return {
        "source_ip": source_ip,
        "label": label,
        "confidence": confidence
    }
