
import os
import sqlite3
import json
from google import genai
from dotenv import load_dotenv

load_dotenv()

SCHEMA_CONTEXT = """
TABLE threat_log (
    id INTEGER PRIMARY KEY,
    timestamp DATETIME,
    source_ip VARCHAR(50),
    label VARCHAR(50),
    confidence FLOAT,
    historical_label VARCHAR(50),
    ai_diagnosis VARCHAR(50),
    final_forensic_label VARCHAR(50),
    forensic_reasoning TEXT,
    final_forensic_conf VARCHAR(20)
)
TABLE firewall_rule (
    id INTEGER PRIMARY KEY,
    ip_address VARCHAR(50),
    timestamp DATETIME,
    status VARCHAR(20),
    reason VARCHAR(255),
    ban_mode VARCHAR(20)
)
"""

def soc_chat_analyst(message, api_key=None, history=[]):
    if not api_key:
        api_key = os.getenv("GEMINI_API_KEY")
    
    if not api_key:
        return "Critical Alert: GenAI Analyst offline. Please configure GEMINI_API_KEY for conversational SOC discovery."

    try:
        client = genai.Client(api_key=api_key)
        
        # System Prompt for NL2SQL and Explanation
        system_instructions = f"""
        You are the 'AdvancedIDS GenAI Senior SOC Analyst'. 
        You have direct access to the ids.db SQLite database with the following schema:
        {SCHEMA_CONTEXT}

        INSTRUCTIONS:
        1. If the user asks a natural language question about threats, logs, or bans, your FIRST priority is to generate a valid SQLite SELECT query.
        2. Execute the query and then explain the results in a concise, technical manner.
        3. If no query is needed (e.g. "What's your name?"), answer directly as a security expert.
        4. NEVER allow any Data Modification (no INSERT, UPDATE, DELETE).
        5. Return ONLY the raw SQL string without any JSON formatting. Do NOT wrap it in a JSON object.
        """

        # Logic: First, decide if a DB search is needed
        decision_prompt = f"{system_instructions}\n\nUSER QUERY: {message}\n\nShould we search the database? If yes, provide ONLY the SQL SELECT. If no, say 'NO_SQL: [your response]'."
        
        resp = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=decision_prompt
        )
        raw_text = resp.text.strip()

        if "SELECT" in raw_text.upper() and "FROM" in raw_text.upper():
            # Clean SQL
            clean_sql = raw_text.replace("```sql", "").replace("```", "").strip()
            # Safety check
            if "DROP" in clean_sql.upper() or "DELETE" in clean_sql.upper():
                return "Safety Violation: Malicious SQL patterns detected. Discovery session reset."
            
            # Execute
            try:
                db_path = os.path.join(os.getcwd(), 'instance', 'ids.db')
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute(clean_sql)
                rows = cursor.fetchall()
                cols = [d[0] for d in cursor.description]
                results = [dict(zip(cols, r)) for r in rows][:10] # limit to 10 for LLM context
                conn.close()

                # Explain results
                final_prompt = f"The SOC operator asked: {message}\nThe database returned: {json.dumps(results)}\nProvide a 2-paragraph expert summary and threat attribution based on this data."
                final_resp = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=final_prompt
                )
                return final_resp.text
            except Exception as e:
                return f"Database Discovery Error: {str(e)}\nAttempted SQL: `{clean_sql}`"
        
        if "NO_SQL:" in raw_text:
            return raw_text.replace("NO_SQL:", "").strip()
            
        return raw_text

    except Exception as e:
        return f"AI Analyst Exception: {str(e)}"
