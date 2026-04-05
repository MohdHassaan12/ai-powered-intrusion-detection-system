import os
from google import genai
from dotenv import load_dotenv

load_dotenv()

def get_forensic_analysis(log_data, api_key=None):
    """
    Uses Google Gemini 1.5 Flash to generate a high-fidelity forensic incident report.
    Combines neural classification, OSINT reputation, and binary signature matches.
    """
    if not api_key:
        api_key = os.getenv("GEMINI_API_KEY")
        
    if not api_key:
        return "Gemini API key is not configured. Please add GEMINI_API_KEY to your .env file for AI forensic insights."

    try:
        client = genai.Client(api_key=api_key)
        
        # Structure the incident for the LLM
        prompt = f"""
        You are a top-tier SOC Forensic Analyst. Analyze the following Intrusion Detection alert:
        
        [INCIDENT TELEMETRY]
        Flow ID: {log_data.get('flow_id')}
        Source IP: {log_data.get('source_ip')}
        AI Diagnosis: {log_data.get('label')}
        Neural Confidence: {log_data.get('confidence')}
        DPI Signatures: {log_data.get('reasoning')}
        Historical Label: {log_data.get('historical_label')}
        
        [REQUIREMENTS]
        1. Contextual summary of the threat.
        2. Threat Attribution: Based on signatures/behavior, what kind of actor is this?
        3. Recommended Actions: Provide 3 exact system commands (e.g. iptables, pfctl) for the operator.
        
        Format your response using bold headings. Be professional and technical.
        """
        
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        return response.text
    except Exception as e:
        return f"GenAI Analysis Failure: {str(e)}"

def get_strategic_intel_summary(recent_logs, active_bans=[], api_key=None):
    """
    Analyzes a cluster of recent incidents to find overarching attack narratives.
    Now includes Phase 1 active bans and Phase 3 OSINT context.
    """
    if not api_key:
        api_key = os.getenv("GEMINI_API_KEY")

    if not api_key: return "GenAI Strategic Layer Disabled."

    try:
        client = genai.Client(api_key=api_key)
        
        # Prepare log summary with reputation and connection pairs
        log_txt = "\n".join([f"Src: {l['source_ip']} -> Dst: {l.get('dest_ip', 'Internal Node')}, Threat: {l['label']}, OSINT: {l.get('reputation', 0)}%" for l in recent_logs])
        ban_txt = ", ".join(active_bans) if active_bans else "None"
        
        prompt = f"""
        You are the 'AdvancedIDS Chief Strategic Analyst'. 
        [SOC TOPOLOGY & THREAT DATA]
        RECENT NETWORK EDGES:
        {log_txt}
        
        [SYSTEM DEFENSE STATE]
        CURRENTLY BLOCKED IPs: {ban_txt}
        
        [REQUIREMENTS]
        1. Contextual summary of the recent threat cluster and observed communication pairs.
        2. Threat Attribution: Identify any 'Lateral Movement' patterns or reconnaissance clusters.
        3. Attack Path Forecast: Predict the most likely next target internal IP or service based on the topology.
        4. Strategic Recommendation: Specific mitigations for the forecasted attack path.
        
        Provide a 3-paragraph Strategic Intelligence & Prediction Summary. Use professional, high-level security terminology.
        """
        
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt
        )
        return response.text
    except Exception as e:
        return f"Strategic synthesis failed: {str(e)}"
