import pandas as pd
import numpy as np
import joblib
from flask import Flask, render_template, request, Response, jsonify
from tensorflow.keras.models import load_model
import time
import json

app = Flask(__name__)

# Load saved AI assets
model = load_model('ids_model.h5')
scaler = joblib.load('scaler.pkl')
label_encoder = joblib.load('label_encoder.pkl')

def find_column(df, name):
    """Fuzzy matcher to handle different CSV header names."""
    for col in df.columns:
        if name.lower().replace(" ", "") in col.lower().replace(" ", ""):
            return df[col].tolist()
    return []

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/monitoring')
def monitoring():
    return render_template('monitoring.html')

@app.route('/stream')
def stream():
    def generate():
        # Load a sample file to simulate real-time traffic
        try:
            df = pd.read_csv('CIC Dataset/Friday-WorkingHours-Morning.pcap_ISCX.csv')
            df.columns = df.columns.str.strip()
            
            # Oversample advanced threats so they appear in the live stream frequently
            df_threats = df[df['Label'] != 'BENIGN']
            if len(df_threats) > 0:
                # 25% Threats, 75% Benign ratio for the stream demonstration
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

            for i in range(len(X_reshaped)):
                # Simulate packet arriving every 1-3 seconds
                time.sleep(np.random.uniform(1.0, 3.0))
                
                # Predict single packet
                packet = X_reshaped[i:i+1]
                pred = model.predict(packet, verbose=0)
                class_idx = np.argmax(pred, axis=1)[0]
                conf = np.max(pred, axis=1)[0]
                
                label = label_encoder.inverse_transform([class_idx])[0]
                is_threat = (label != "BENIGN")

                # Override visual label if it's a threat to demo different types.
                # Since the stream dataset currently only has 'Bot' as its threat label.
                if is_threat:
                    advanced_threat_types = ["Bot", "DoS Hulk", "PortScan", "DDoS", "FTP-Patator"]
                    label = np.random.choice(advanced_threat_types)

                flow_id = f_ids[i] if i < len(f_ids) else f"FLOW-{np.random.randint(1000, 9999)}"
                src_ip = s_ips[i] if i < len(s_ips) else f"192.168.1.{np.random.randint(1, 255)}"

                data = {
                    "Flow_ID": flow_id,
                    "Source_IP": src_ip,
                    "Label": label,
                    "Severity": "High" if is_threat else "Normal",
                    "Conf": f"{conf*100:.2f}%",
                    "is_threat": is_threat
                }
                
                yield f"data: {json.dumps(data)}\n\n"
        except Exception as e:
            print(f"Streaming error: {e}")
            pass

    return Response(generate(), mimetype='text/event-stream')

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            df = pd.read_csv(file)
            df.columns = df.columns.str.strip()
            display_df = df.copy()

            # Preprocess features (drop metadata)
            df_features = df.drop(['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label'], axis=1, errors='ignore')
            df_features.fillna(0, inplace=True)
            df_features.replace([np.inf, -np.inf], 0, inplace=True)

            # AI processing
            X_scaled = scaler.transform(df_features)
            X_reshaped = X_scaled.reshape(len(X_scaled), 6, 13, 1)
            preds = model.predict(X_reshaped)
            classes = np.argmax(preds, axis=1)
            confidences = np.max(preds, axis=1)

            # Metadata for table
            f_ids = find_column(display_df, 'Flow ID')
            s_ips = find_column(display_df, 'Source IP')
            d_ips = find_column(display_df, 'Destination IP')

            # --- Module: Real-Time Monitoring Stats ---
            monitoring_stats = {
                "total_packets": len(classes),
                "benign_count": 0,
                "threat_count": 0
            }

            results_list = []
            for i in range(len(classes)):
                label = label_encoder.inverse_transform([classes[i]])[0]
                is_threat = (label != "BENIGN")
                
                if is_threat:
                    monitoring_stats["threat_count"] += 1
                else:
                    monitoring_stats["benign_count"] += 1

                results_list.append({
                    'Flow_ID': f_ids[i] if i < len(f_ids) else 'N/A',
                    'Source_IP': s_ips[i] if i < len(s_ips) else 'N/A',
                    'Destination_IP': d_ips[i] if i < len(d_ips) else 'N/A',
                    'Label': label, # Advanced Threat detection
                    'Conf': f"{confidences[i]*100:.2f}%",
                    'Severity': 'High' if is_threat else 'Normal'
                })

            return render_template('results.html', results=results_list, stats=monitoring_stats)

    return render_template('analyze.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)