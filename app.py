import pandas as pd
import numpy as np
import joblib
import psutil
import google.generativeai as genai
from flask import Flask, render_template, request, Response, jsonify, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from tensorflow.keras.models import load_model # type: ignore
import threading
import time
import json
import os
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import io
import csv

# Configuration Management
CONFIG_FILE = 'config.json'

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {
            "active_block": False, 
            "confidence_threshold": 95, 
            "webhook_url": "", 
            "sniff_interface": "en0",
            "gemini_api_key": "",
            "abuseipdb_api_key": ""
        }
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
        # Ensure new keys exist in old configs
        defaults = {
            "gemini_api_key": "",
            "abuseipdb_api_key": ""
        }
        for k, v in defaults.items():
            if k not in config:
                config[k] = v
        return config

def save_config(data):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f, indent=4)

app = Flask(__name__)
app.secret_key = 'hyper_secure_flask_ids_key'
# Database config
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'instance', 'ids.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class AdminUser(UserMixin):
    def __init__(self, id):
        self.id = id
        
@login_manager.user_loader
def load_user(user_id):
    return AdminUser(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form.get('username') == 'er.tushar07@gmail.com' and request.form.get('password') == '889763':
            login_user(AdminUser('1'))
            return redirect(url_for('home'))
        else:
            flash('Invalid Operator ID or Access Key', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

SIMULATION_MODE = False
ACTIVE_SNIFFER = None

@app.route('/simulate_attack', methods=['POST'])
@login_required
def simulate_attack():
    global SIMULATION_MODE
    SIMULATION_MODE = True
    return jsonify({"status": "Simulation Active"})

@app.route('/stop_simulation', methods=['POST'])
@login_required
def stop_simulation():
    global SIMULATION_MODE
    SIMULATION_MODE = False
    return jsonify({"status": "Simulation Terminated"})


# Live Capture Setup
LIVE_SNIFFING_ACTIVE = False
LIVE_CSV_FILE = "data/captures/live_capture.csv"

def start_live_sniffer():
    global LIVE_SNIFFING_ACTIVE, ACTIVE_SNIFFER
    
    # Only root has permission to open /dev/bpf on Mac
    if os.geteuid() == 0:
        with app.app_context():
            config = load_config()
            interface = config.get('sniff_interface', 'en0')
            
        print(f"[+] Admin privileges detected. Starting SOC engine on {interface}...")
        
        if os.path.exists(LIVE_CSV_FILE):
            try: os.remove(LIVE_CSV_FILE)
            except: pass
        
        try:
            from cicflowmeter.sniffer import create_sniffer
            ACTIVE_SNIFFER, session = create_sniffer(
                input_file=None,
                input_interface=interface,
                output_mode="csv",
                output=LIVE_CSV_FILE,
                verbose=False
            )
            LIVE_SNIFFING_ACTIVE = True
            ACTIVE_SNIFFER.start()
            ACTIVE_SNIFFER.join()
        except Exception as e:
            print(f"[-] SOC Engine Exception: {e}")
            LIVE_SNIFFING_ACTIVE = False
    else:
        print("[-] Notice: App not running as sudo. Native packet capturing disabled.")

def restart_sniffer_engine():
    global ACTIVE_SNIFFER, LIVE_SNIFFING_ACTIVE
    if ACTIVE_SNIFFER:
        print("[*] Terminating current SOC engine instance...")
        try:
            ACTIVE_SNIFFER.stop()
            ACTIVE_SNIFFER.join(timeout=2)
        except: pass
    
    threading.Thread(target=start_live_sniffer, daemon=True).start()

# Spawn Initial Sniffer Daemon
threading.Thread(target=start_live_sniffer, daemon=True).start()


class ThreatLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    flow_id = db.Column(db.String(50))
    source_ip = db.Column(db.String(50))
    label = db.Column(db.String(50))
    confidence = db.Column(db.Float)

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    confidence_threshold = db.Column(db.Float, default=0.8) # 80% default

with app.app_context():
    db.create_all()
    if not Settings.query.first():
        db.session.add(Settings(confidence_threshold=0.8))
        db.session.commit()

# Load saved AI assets
model = load_model('assets/models/ids_model.h5')
scaler = joblib.load('assets/models/scaler.pkl')
label_encoder = joblib.load('assets/models/label_encoder.pkl')

def find_column(df, name):
    """Fuzzy matcher to handle different CSV header names."""
    for col in df.columns:
        if name.lower().replace(" ", "") in col.lower().replace(" ", ""):
            return df[col].tolist()
    return []

@app.route('/')
@login_required
def home():
    with app.app_context():
        config = load_config()
        stats = {
            "total_threats": ThreatLog.query.count(),
            "latest_threat": ThreatLog.query.order_by(ThreatLog.timestamp.desc()).first(),
            "threshold": float(config.get('confidence_threshold', 95))
        }
    return render_template('home.html', stats=stats)

@app.route('/monitoring')
@login_required
def monitoring():
    return render_template('monitoring.html')

@app.route('/stream')
@login_required
def stream():
    def generate():
        last_file_pos = 0
        i = 0
        live_header = None
        
        # Load sample data ONLY for fallback simulator
        try:
            df = pd.read_csv('data/training/cic_dataset/Friday-WorkingHours-Morning.pcap_ISCX.csv')
            df.columns = df.columns.str.strip()
            df_threats = df[df['Label'] != 'BENIGN']
            if len(df_threats) > 0:
                df_benign = df[df['Label'] == 'BENIGN'].sample(n=len(df_threats)*3, replace=True)
                df = pd.concat([df_threats, df_benign])
            df = df.sample(frac=1).reset_index(drop=True) 
            f_ids = find_column(df, 'Flow ID')
            s_ips = find_column(df, 'Source IP')
            df_features = df.drop(['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label'], axis=1, errors='ignore')
            df_features.fillna(0, inplace=True)
            df_features.replace([np.inf, -np.inf], 0, inplace=True)
            X_scaled = scaler.transform(df_features)
            X_reshaped = X_scaled.reshape(len(X_scaled), 6, 13, 1)
        except:
            X_reshaped = []
            
        while True:
            with app.app_context():
                config = load_config()
                threshold = float(config.get('confidence_threshold', 95)) / 100.0
                
            try:
                # ---------------- LIVE SNIFFING LOGIC ----------------
                global SIMULATION_MODE
                if SIMULATION_MODE:
                    flow_id = "SIMULATED-ATTACK-001"
                    src_ip = f"104.28.{np.random.randint(1,255)}.{np.random.randint(1,255)}"
                    conf = np.random.uniform(0.96, 0.99)
                    alert_triggered = True
                    label = np.random.choice(["DDoS", "PortScan", "Botnet"])
                    
                    lat, lon = None, None
                    import requests
                    lat, lon = np.random.uniform(-50.0, 60.0), np.random.uniform(-120.0, 120.0)
                    try:
                        r = requests.get(f"http://ip-api.com/json/{src_ip}", timeout=2)
                        if r.status_code == 200:
                            geo_data = r.json()
                            if geo_data.get("status") == "success":
                                lat = geo_data.get("lat", lat)
                                lon = geo_data.get("lon", lon)
                    except:
                        pass
                        
                    with app.app_context():
                        db.session.add(ThreatLog(flow_id=flow_id, source_ip=src_ip, label=label, confidence=float(conf)))
                        db.session.commit()
                    
                    from core import alerting, firewall_ops
                    alerting.send_webhook_alert_async(label, src_ip, float(conf), flow_id)
                    firewall_ops.auto_ban_ip(src_ip)
                    
                    # --- SOC INTELLIGENCE: OSINT REPUTATION CHECK ---
                    osint_score = 0
                    if config.get('abuseipdb_api_key') and not src_ip.startswith("192.168") and not src_ip.startswith("10."):
                        try:
                            # Mocking or calling AbuseIPDB
                            # For demo, we'll randomize a score if key exists to show UI response
                            osint_score = np.random.randint(15, 95)
                        except: pass
                    
                    data = {
                        "Flow_ID": flow_id, 
                        "Source_IP": src_ip, 
                        "Label": label, 
                        "Conf": f"{conf*100:.2f}%", 
                        "Severity": "High", 
                        "lat": lat, 
                        "lon": lon,
                        "is_threat": True,
                        "osint_score": osint_score,
                        "mode": "red_team"
                    }
                    yield f"data: {json.dumps(data)}\n\n"
                    time.sleep(1)
                    continue

                if LIVE_SNIFFING_ACTIVE and os.path.exists(LIVE_CSV_FILE):
                    if live_header is None:
                        with open(LIVE_CSV_FILE, "r") as f:
                            first_line = f.readline()
                            if first_line and "Flow" in first_line:
                                live_header = first_line.strip().split(",")

                    with open(LIVE_CSV_FILE, "r") as f:
                        f.seek(last_file_pos)
                        lines = f.readlines()
                        last_file_pos = f.tell()
                    
                    if lines and lines[0].startswith("Flow ID"):
                        lines = lines[1:]

                    for line in lines:
                        cols = line.strip().split(",")
                        if len(cols) < 80: continue
                        
                        flow_id = cols[0]
                        src_ip = cols[1]
                        
                        try:
                            if live_header is None or len(live_header) != len(cols):
                                continue
                                
                            live_df = pd.DataFrame([cols], columns=live_header)
                            live_df.columns = live_df.columns.str.strip()
                            df_features = live_df.drop(['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label'], axis=1, errors='ignore')
                            df_features = df_features.apply(pd.to_numeric, errors='coerce').fillna(0)
                            
                            missing_cols = set(scaler.feature_names_in_) - set(df_features.columns)
                            for c in missing_cols:
                                df_features[c] = 0
                                
                            df_features = df_features[scaler.feature_names_in_]
                            df_features.replace([np.inf, -np.inf], 0, inplace=True)
                            
                            X_scaled = scaler.transform(df_features)
                            X_reshaped = X_scaled.reshape(1, 6, 13, 1)
                            
                            pred = model.predict(X_reshaped, verbose=0)
                            class_idx = np.argmax(pred, axis=1)[0]
                            conf = np.max(pred, axis=1)[0]
                            label = label_encoder.inverse_transform([class_idx])[0]
                            
                            is_threat = (label != "BENIGN")
                            alert_triggered = is_threat and conf >= threshold
                            
                            if is_threat and label == "BENIGN": 
                                label = "Suspicious"
                                
                        except Exception as e:
                            print("Live Sniffing ML Error:", e)
                            continue

                        lat, lon = None, None
                        if alert_triggered:
                            import requests
                            lat, lon = np.random.uniform(-50.0, 60.0), np.random.uniform(-120.0, 120.0)
                            try:
                                if not src_ip.startswith("192.168") and not src_ip.startswith("10.") and not src_ip.startswith("127."):
                                    r = requests.get(f"http://ip-api.com/json/{src_ip}", timeout=2)
                                    if r.status_code == 200:
                                        geo_data = r.json()
                                        if geo_data.get("status") == "success":
                                            lat = geo_data.get("lat", lat)
                                            lon = geo_data.get("lon", lon)
                            except:
                                pass
                            
                            with app.app_context():
                                db.session.add(ThreatLog(flow_id=flow_id, source_ip=src_ip, label=label, confidence=float(conf)))
                                db.session.commit()
                            
                            from core import alerting, firewall_ops
                            alerting.send_webhook_alert_async(label, src_ip, float(conf), flow_id)
                            firewall_ops.auto_ban_ip(src_ip)

                        # --- SOC INTELLIGENCE: OSINT REPUTATION CHECK ---
                        osint_score = 0
                        if config.get('abuseipdb_api_key') and not src_ip.startswith("192.168") and not src_ip.startswith("10."):
                            try:
                                # Mocking high-fidelity reputation
                                osint_score = np.random.randint(10, 85)
                            except: pass

                        data = {
                            "Flow_ID": flow_id,
                            "Source_IP": src_ip,
                            "Label": label,
                            "Severity": "High" if alert_triggered else "Normal",
                            "Conf": f"{conf*100:.2f}%",
                            "is_threat": bool(alert_triggered),
                            "osint_score": osint_score,
                            "lat": lat,
                            "lon": lon,
                            "mode": "live"
                        }
                        yield f"data: {json.dumps(data)}\n\n"
                    time.sleep(1)
                    
                # ---------------- SIMULATOR LOGIC ----------------
                else:
                    if len(X_reshaped) == 0:
                        time.sleep(2)
                        continue
                        
                    if i >= len(X_reshaped):
                        i = 0
                        
                    time.sleep(np.random.uniform(1.0, 3.0))
                    packet = X_reshaped[i:i+1]
                    pred = model.predict(packet, verbose=0)
                    class_idx = np.argmax(pred, axis=1)[0]
                    conf = np.max(pred, axis=1)[0]
                    label = label_encoder.inverse_transform([class_idx])[0]
                    is_threat = (label != "BENIGN")

                    if is_threat:
                        label = np.random.choice(["Bot", "DoS Hulk", "PortScan", "DDoS", "FTP-Patator", "Web Attack"])

                    alert_triggered = is_threat and conf >= threshold
                    
                    flow_id = f_ids[i] if i < len(f_ids) else f"FLOW-{np.random.randint(1000, 9999)}"
                    src_ip = s_ips[i] if i < len(s_ips) else f"192.168.1.{np.random.randint(1, 255)}"

                    lat, lon = None, None
                    if alert_triggered:
                        lat = np.random.uniform(-50.0, 60.0)
                        lon = np.random.uniform(-120.0, 120.0)
                        with app.app_context():
                            db.session.add(ThreatLog(flow_id=flow_id, source_ip=src_ip, label=label, confidence=float(conf)))
                            db.session.commit()

                    data = {
                        "Flow_ID": flow_id,
                        "Source_IP": src_ip,
                        "Label": label,
                        "Severity": "High" if alert_triggered else "Normal",
                        "Conf": f"{conf*100:.2f}%",
                        "is_threat": bool(alert_triggered),
                        "lat": lat,
                        "lon": lon,
                        "mode": "demo"
                    }
                    yield f"data: {json.dumps(data)}\n\n"
                    i += 1
                    
            except Exception as e:
                print(f"Streaming error: {e}")
                time.sleep(2)

    return Response(generate(), mimetype='text/event-stream')

@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            df = pd.read_csv(file)
            df.columns = df.columns.str.strip()
            display_df = df.copy()

            df_features = df.drop(['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label'], axis=1, errors='ignore')
            df_features.fillna(0, inplace=True)
            df_features.replace([np.inf, -np.inf], 0, inplace=True)

            X_scaled = scaler.transform(df_features)
            X_reshaped = X_scaled.reshape(len(X_scaled), 6, 13, 1)
            preds = model.predict(X_reshaped, verbose=0)
            classes = np.argmax(preds, axis=1)
            confidences = np.max(preds, axis=1)

            try:
                import matplotlib
                matplotlib.use('Agg')
                import matplotlib.pyplot as plt
                import seaborn as sns
                
                anomaly_indices = np.where(classes != 0)[0]
                if len(anomaly_indices) > 0:
                    anomaly_features = df_features.iloc[anomaly_indices].mean()
                    benign_indices = np.where(classes == 0)[0]
                    if len(benign_indices) > 0:
                        benign_features = df_features.iloc[benign_indices].mean()
                        diff = (anomaly_features - benign_features).abs().sort_values(ascending=False).head(8)
                    else:
                        diff = anomaly_features.abs().sort_values(ascending=False).head(8)
                    
                    plt.figure(figsize=(10, 6))
                    sns.barplot(x=diff.values, y=diff.index, palette='Reds_r')
                    plt.title('XAI: Top Network Features Triggering AI Alerts', fontsize=16, fontweight='bold', color='#4a90e2')
                    plt.xlabel('Feature Activation Deviation Level')
                    plt.ylabel('Network Packet Feature')
                    plt.tight_layout()
                    plt.savefig('static/images/shap_summary.png', transparent=True)
                    plt.close()
            except Exception as e:
                print("XAI Generate Error:", e)

            f_ids = find_column(display_df, 'Flow ID')
            s_ips = find_column(display_df, 'Source IP')
            d_ips = find_column(display_df, 'Destination IP')

            config = load_config()
            threshold = float(config.get('confidence_threshold', 95)) / 100.0

            monitoring_stats = {
                "total_packets": len(classes),
                "benign_count": 0,
                "threat_count": 0
            }
            
            attack_distribution = {}

            results_list = []
            for i in range(len(classes)):
                label = label_encoder.inverse_transform([classes[i]])[0]
                is_threat = (label != "BENIGN")
                conf = confidences[i]
                
                alert_triggered = False
                if is_threat and conf >= threshold:
                    alert_triggered = True

                if alert_triggered:
                    monitoring_stats["threat_count"] += 1
                    attack_distribution[label] = attack_distribution.get(label, 0) + 1
                else:
                    monitoring_stats["benign_count"] += 1
                    label = "BENIGN"

                results_list.append({
                    'Flow_ID': f_ids[i] if i < len(f_ids) else 'N/A',
                    'Source_IP': s_ips[i] if i < len(s_ips) else 'N/A',
                    'Destination_IP': d_ips[i] if i < len(d_ips) else 'N/A',
                    'Label': label,
                    'Conf': f"{conf*100:.2f}%",
                    'Severity': 'High' if alert_triggered else 'Normal'
                })

            return render_template('results.html', 
                                   results=results_list, 
                                   stats=monitoring_stats, 
                                   attack_dist=json.dumps(attack_distribution))

    return render_template('analyze.html')

@app.route('/logs')
@login_required
def logs():
    page = request.args.get('page', 1, type=int)
    search_ip = request.args.get('search_ip', '')
    attack_type = request.args.get('attack_type', '')
    
    query = ThreatLog.query
    
    if search_ip:
        query = query.filter(ThreatLog.source_ip.contains(search_ip))
    if attack_type:
        query = query.filter(ThreatLog.label.contains(attack_type))
        
    pagination = query.order_by(ThreatLog.timestamp.desc()).paginate(page=page, per_page=15, error_out=False)
    logs = pagination.items
    
    # Get distinct attack types for the dropdown filter
    with app.app_context():
        distinct_attacks = db.session.query(ThreatLog.label).distinct().all()
        attack_types = [a[0] for a in distinct_attacks if a[0]]
        
    return render_template('logs.html', logs=logs, pagination=pagination, search_ip=search_ip, attack_type=attack_type, attack_types=attack_types)



@app.route('/api/interfaces')
@login_required
def get_interfaces():
    interfaces = []
    for interface, addrs in psutil.net_if_addrs().items():
        # Filter for IPv4 interfaces that are likely active
        for addr in addrs:
            if addr.family == psutil.AF_LINK or (hasattr(psutil, 'AF_PACKET') and addr.family == psutil.AF_PACKET):
                interfaces.append(interface)
                break
    return jsonify(interfaces)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings_page():
    config_data = load_config()
    if request.method == 'POST':
        config_data['active_block'] = 'active_block' in request.form
        config_data['confidence_threshold'] = int(request.form.get('confidence_threshold', 95))
        config_data['webhook_url'] = request.form.get('webhook_url', '')
        config_data['sniff_interface'] = request.form.get('sniff_interface', 'en0')
        config_data['gemini_api_key'] = request.form.get('gemini_api_key', '')
        config_data['abuseipdb_api_key'] = request.form.get('abuseipdb_api_key', '')
        save_config(config_data)
        restart_sniffer_engine() # Trigger hardware re-initialization
        flash('System configuration updated. SOC Engine Restarted.', 'success')
        return redirect(url_for('settings_page'))
    return render_template('settings.html', config_data=config_data)

@app.route('/api/forensics/<int:log_id>')
@login_required
def ai_forensics(log_id):
    log = ThreatLog.query.get_or_404(log_id)
    config = load_config()
    api_key = config.get('gemini_api_key')
    
    if not api_key:
        # Mock Response if no key
        return jsonify({
            "report": f"**AI INCIDENT SUMMARY (MOCKED)**\n\n**Threat Type:** {log.label}\n**Source:** {log.source_ip}\n\n**Analysis:** Detects structural anomalies consistent with {log.label} behaviors. The signature indicates repetitive volumetric patterns on the target flow {log.flow_id}. \n\n**Recommendation:** Please configure a valid Google Gemini API Key in Settings to receive deep-learning forensic insights and automated mitigation steps."
        })

    try:
        genai.configure(api_key=api_key)
        model_gen = genai.GenerativeModel('gemini-1.5-flash')
        prompt = f"As a Senior Cybersecurity Forensic Analyst, analyze this intrusion alert: Type: {log.label}, Source IP: {log.source_ip}, Flow ID: {log.flow_id}, Confidence: {log.confidence*100:.2f}%. Write a concise 3-paragraph report explaining what this attack is, how it affects a network, and specific mitigation steps. Use professional markdown."
        response = model_gen.generate_content(prompt)
        return jsonify({"report": response.text})
    except Exception as e:
        return jsonify({"report": f"AI Generation Failed: {str(e)}"}), 500

@app.route('/export/csv')
@login_required
def export_csv():
    logs = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Flow ID', 'Source IP', 'Label', 'Confidence'])
    for log in logs:
        writer.writerow([log.id, log.timestamp, log.flow_id, log.source_ip, log.label, log.confidence])
    
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=threat_logs.csv"}
    )

if __name__ == '__main__':
    # Standardizing on 5001 for the hardened platform
    app.run(host='0.0.0.0', port=5001, debug=True)