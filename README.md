<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=32&pause=1000&color=00F7FF&center=true&vCenter=true&width=800&lines=AdvancedIDS+Enterprise+SOC+Platform;Neural+Network+Threat+Detection;Google+Gemini+AI+Forensics;Real-Time+Network+Interdiction" alt="Typing SVG" />

<br/>

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.20-orange?style=for-the-badge&logo=tensorflow&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-black?style=for-the-badge&logo=flask&logoColor=white)
![Google Gemini](https://img.shields.io/badge/Google_Gemini-Forensics-8E75B2?style=for-the-badge&logo=google-gemini&logoColor=white)
![Design](https://img.shields.io/badge/UI/UX-Glassmorphism-FF69B4?style=for-the-badge)

<br/>

> **A professional-grade, real-time Security Operations Center (SOC) platform. This system utilizes a Convolutional Neural Network (CNN) for high-speed traffic classification, integrated with Google Gemini for automated neural forensics and a specialized Red Team simulation engine.**

</div>

---

## 🏛️ Platform Architecture

AdvancedIDS is built on a modular four-tier architecture designed for operational speed and forensic accuracy.

### 1. **Neural Detection Engine**
A CNN-based inference layer that processes raw network flows captured via `cicflowmeter`. 
- **Input Layers**: 78 numerical features reshaped into (6×13×1) spatial matrices.
- **Confidence Thresholding**: Real-time severity tagging based on high-probability malicious patterns.

### 2. **AI Forensics & Intelligence**
Integrated with **Google Gemini (LLM)** to provide "Neural Incident Reports".
- Automated generation of 3-paragraph forensic summaries for any flagged threat.
- Includes attack origin analysis, impact assessment, and specific mitigation protocols.

### 3. **Operational Control (Ops Control)**
A dual-mode simulation and interdiction layer.
- **Red Team Fire**: Manual trigger for Botnet, DDoS, and PortScan simulations.
- **Operational Kill Switch**: Instant termination of all active simulations via the `/stop_simulation` backend.

### 4. **Live Centre (Live Stream)**
Server-Sent Events (SSE) driven dashboard providing 10ms latency updates of all network activity.

---

## 🏗️ Technical Stack

| Layer | Technology | Role |
|-------|------------|------|
| **Core Engine** | Python 3.11, `psutil`, `scapy` | Logic & Network Hook |
| **Parsing** | `cicflowmeter` | PCAP to Flow Feature Conversion |
| **Model** | TensorFlow / Keras | CNN Traffic Classification |
| **Forensics** | Google Gemini (1.5-Flash) | Automated Neural Reporting |
| **Web UI** | Flask 3.1, Vanilla CSS | Glassmorphic SOC Dashboard |
| **Database** | SQLite + SQLAlchemy | Hardened Persistence Layer |

---

## 🚀 Deployment Guide

> [!WARNING]
> **Network Sniffing Requires Root Privileges**: Because the platform hooks into raw network interfaces for live capture, it **must** be executed with `sudo`.

### Prerequisites
- **Python 3.11+** installed in a virtual environment.
- **Network Interface**: macOS (`en0`, `lo0`) or Linux (`eth0`, `wlan0`).

### 1. Installation
```bash
# Clone and enter directory
git clone https://github.com/MohdHassaan12/ai-powered-intrusion-detection-system.git
cd ai-powered-intrusion-detection-system

# Prepare the environment
python -m venv mac_venv
source mac_venv/bin/activate
pip install -r requirements.txt
```

### 2. Running the Platform
```bash
# Execute with root privileges
sudo ./.venv/mac_venv/bin/python app.py
```

### 3. Accessing the Dashboard
Open your secure portal at: **[http://127.0.0.1:5001](http://127.0.0.1:5001)**
- **User**: `er.tushar07@gmail.com`
- **PIN**: `889763`

---

## ⚙️ Configuration Management

The platform handles its state via `config.json` (auto-generated in the root directory). You can modify these settings directly in the **Settings** tab.

- `sniff_interface`: The hardware interface to monitor (e.g., `en0`).
- `gemini_api_key`: Required for generating AI Forensic Reports.
- `confidence_threshold`: Probability % required to trigger a "High" severity alert.

---

## 🔮 Roadmap
- [ ] **Phase 4**: Migration to `google.genai` SDK from deprecated package.
- [ ] **Phase 5**: Integration of AlienVault OTX / VirusTotal OSINT feeds.
- [ ] **Phase 6**: Automated IP Blacklisting (IPS mode) via OS-level firewall hooks.

---

<div align="center">

**Enterprise SOC Platform | Optimized for Precision Security**
Made with 🛡️ and 🧠 by [Mohd Hassaan](https://github.com/MohdHassaan12)

</div>
