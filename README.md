<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=30&pause=1000&color=00F7FF&center=true&vCenter=true&width=700&lines=AI-Powered+Intrusion+Detection+System;Real-Time+Network+Threat+Detection;Deep+Learning+%2B+Flask+Dashboard" alt="Typing SVG" />

<br/>

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python&logoColor=white)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.20-orange?style=for-the-badge&logo=tensorflow&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-black?style=for-the-badge&logo=flask&logoColor=white)
![Keras](https://img.shields.io/badge/Keras-3.13-red?style=for-the-badge&logo=keras&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.8-yellow?style=for-the-badge&logo=scikit-learn&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

<br/>

> **A production-ready, real-time Network Intrusion Detection System powered by a Convolutional Neural Network (CNN), capable of classifying network traffic into benign or malicious with high confidence — served through a live Flask dashboard.**

</div>

---

## 🚨 Problem Statement

With the rapid growth of internet-connected devices, cybersecurity threats have become increasingly sophisticated and frequent. Traditional rule-based Intrusion Detection Systems (IDS) fail to detect **novel, zero-day, or polymorphic attacks** because they rely on static signatures.

**The core challenges are:**

| Challenge | Traditional IDS | This AI-IDS |
|-----------|----------------|-------------|
| Novel attack detection | ❌ Fails on unseen patterns | ✅ Learns from traffic features |
| Speed | ⚠️ Slow rule matching | ✅ Real-time stream inference |
| Accuracy | ⚠️ High false positives | ✅ CNN-based classification |
| Scalability | ❌ Manual rule updates | ✅ Retrain on new data |

**This project solves these challenges** by training a CNN on the CIC-IDS2017 benchmark dataset and deploying it as a real-time monitoring dashboard — detecting threats in live network traffic streams with per-packet confidence scores.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────┐
│                 Network Traffic                  │
│         (Live Stream / Uploaded CSV)            │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│             Data Preprocessing Layer            │
│  • Drop metadata (IP, FlowID, Timestamp)        │
│  • Fill NaN → 0  │  Inf → 0                    │
│  • StandardScaler normalization                 │
│  • Reshape: (N, 78) → (N, 6, 13, 1)            │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│            CNN Model  (ids_model.h5)            │
│                                                 │
│  Input (6×13×1)                                 │
│     │                                           │
│  Conv2D(32, 1×1) → BatchNorm → ReLU            │
│     │                                           │
│  Conv2D(64, 1×1) → BatchNorm → ReLU            │
│     │                                           │
│  Flatten → Dense(128) → Dropout(0.5)           │
│     │                                           │
│  Softmax Output → [Class, Confidence]           │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│              Flask Web Application              │
│                                                 │
│   /             → Home Dashboard               │
│   /monitoring   → Live SSE Stream View         │
│   /stream       → Server-Sent Events (SSE)     │
│   /analyze      → CSV Upload & Batch Analysis  │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│              Real-Time Web Dashboard            │
│  • Live packet feed with threat classification  │
│  • Confidence scores per packet                 │
│  • Severity tagging: High / Normal              │
│  • Batch analysis with stat summary             │
└─────────────────────────────────────────────────┘
```

### 🧠 CNN Architecture Detail

```
Layer (type)              Output Shape        Param #
─────────────────────────────────────────────────────
Conv2D (32 filters, 1×1)  (None, 6, 13, 32)    160
BatchNormalization         (None, 6, 13, 32)    128
Conv2D (64 filters, 1×1)  (None, 6, 13, 64)  2,112
BatchNormalization         (None, 6, 13, 64)    256
Flatten                    (None, 4992)            0
Dense (128, ReLU)          (None, 128)        639,104
Dropout (0.5)              (None, 128)             0
Dense (Softmax, n_classes) (None, n)           n×128
─────────────────────────────────────────────────────
Optimizer: Adam  │  Loss: Categorical Crossentropy
```

---

## 📊 Dataset — CIC-IDS2017

The model is trained and evaluated on the **Canadian Institute for Cybersecurity Intrusion Detection System 2017 (CIC-IDS2017)** benchmark dataset — the gold standard for network intrusion detection research.

| Property | Details |
|----------|---------|
| **Source** | University of New Brunswick (UNB), Canada |
| **Collection Period** | Mon–Fri, business-hours traffic |
| **Total Features** | 78 numerical flow-based features |
| **Attack Families** | 14 attack types + BENIGN |
| **Format** | CSV (PCAP-derived via CICFlowMeter) |
| **Used Split** | Thursday Web Attacks (training) + Friday Morning (streaming demo) |

### Attack Classes Detected

```
✅ BENIGN          — Normal network traffic
🔴 Bot             — Botnet C&C communication
🔴 DoS Hulk        — HTTP flood denial of service
🔴 PortScan        — Reconnaissance port scanning
🔴 DDoS            — Distributed denial of service
🔴 FTP-Patator     — FTP brute-force password attack
🔴 Web Attacks     — SQL Injection, XSS, Brute Force
```

### Feature Categories

| Category | Examples |
|----------|---------|
| **Flow Duration** | Flow Duration, Active Mean, Idle Mean |
| **Packet Stats** | Total Fwd/Bwd Packets, Packet Length Mean/Std |
| **Byte Rates** | Flow Bytes/s, Flow Packets/s |
| **TCP Flags** | SYN, ACK, PSH, FIN, RST, URG flag counts |
| **Header Info** | Fwd Header Length, Min/Max Packet Length |

---

## 📈 Results

| Metric | Value |
|--------|-------|
| **Model** | Convolutional Neural Network (CNN) |
| **Input Shape** | (6 × 13 × 1) — 78 features reshaped |
| **Training Epochs** | 2 (fast training demo; extendable) |
| **Batch Size** | 32 |
| **Train / Test Split** | 80% / 20% |
| **Optimizer** | Adam |
| **Loss Function** | Categorical Cross-Entropy |
| **Output** | Multi-class classification with per-class confidence |

### Threat Detection Behavior

- **Live Stream Ratio:** 25% Threats : 75% Benign (oversampled threats for demo visibility)
- **Confidence Display:** Each packet prediction shows confidence % (e.g., `97.43%`)
- **Severity Tagging:** `High` for any non-BENIGN classification, `Normal` for clean traffic
- **Batch Mode:** Upload any CIC-compatible CSV → get full table + stats summary

---

## 🖥️ Screenshots

> 📸 *The dashboard is a dark-themed, interactive web app with live data feeds.*

### 🏠 Home Dashboard
![Home Page](https://via.placeholder.com/900x400/0a0a1a/00F7FF?text=Home+Dashboard+—+AI+IDS)

### 📡 Live Threat Monitoring
![Monitoring Page](https://via.placeholder.com/900x400/0a0a1a/FF4444?text=Live+Threat+Stream+Monitor)

### 🔍 CSV Batch Analysis
![Analyze Page](https://via.placeholder.com/900x400/0a0a1a/00FF88?text=CSV+Upload+%2B+Batch+Analysis+Results)

> **💡 To add real screenshots:** Run the app locally, capture screenshots, save them in a `screenshots/` folder, and update the image paths above.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.11+
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/MohdHassaan12/ai-powered-intrusion-detection-system.git
cd ai-powered-intrusion-detection-system

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Running the Application

```bash
python app.py
```

Then open your browser at: **http://localhost:5001**

### Training the Model (Optional)

> ⚠️ Download the CIC-IDS2017 dataset from [UNB](https://www.unb.ca/cic/datasets/ids-2017.html) first.

```bash
# Place your CSV file in project root, then:
python model.py
```

This saves:
- `ids_model.h5` — trained CNN model
- `scaler.pkl` — StandardScaler
- `label_encoder.pkl` — LabelEncoder

---

## 📁 Project Structure

```
ai-powered-intrusion-detection-system/
│
├── app.py                  # Flask app — routes, SSE stream, analysis
├── model.py                # CNN model architecture + training script
├── ids_model.h5            # Pre-trained CNN model weights
├── scaler.pkl              # Fitted StandardScaler
├── label_encoder.pkl       # Fitted LabelEncoder
├── requirements.txt        # Python dependencies
│
├── CIC Dataset/
│   └── Friday-WorkingHours-Morning.pcap_ISCX.csv   # Stream demo data
│
└── templates/
    ├── home.html           # Landing dashboard
    ├── monitoring.html     # Live threat monitor (SSE)
    ├── analyze.html        # CSV upload page
    ├── results.html        # Analysis results table
    └── bootstrap.html      # Shared base template
```

---

## 🔧 Tech Stack

| Layer | Technology |
|-------|-----------|
| **AI / ML** | TensorFlow 2.20, Keras 3.13, scikit-learn |
| **Web Framework** | Flask 3.1 |
| **Data Processing** | Pandas, NumPy |
| **Real-Time Stream** | Server-Sent Events (SSE) |
| **Serialization** | Joblib (scaler + encoder), HDF5 (model) |
| **Dataset** | CIC-IDS2017 (University of New Brunswick) |

---

## 🔮 Future Improvements

- [ ] Add LSTM / Transformer-based temporal model
- [ ] Integrate with live network interface (via `scapy` / `pyshark`)
- [ ] Deploy to cloud (AWS / GCP / Azure)
- [ ] Add email/Slack alerting for high-severity threats
- [ ] Model retraining pipeline with new data

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made with 🛡️ and 🧠 by [Mohd Hassaan](https://github.com/MohdHassaan12)**

⭐ Star this repo if you found it useful!

</div>
