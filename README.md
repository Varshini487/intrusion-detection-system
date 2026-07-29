# 🔐 Intrusion Detection System (IDS)

A **Network Intrusion Detection System** that combines unsupervised anomaly detection (Isolation Forest) with supervised classification (XGBoost) to detect port scans, brute force attacks, DDoS, and lateral movement in real time.

## 🧠 How It Works (3-layer)

**Layer 1: Feature Extraction**
- Raw network packets → extract features: source IP, dest IP, protocol, port, packet size, duration, flag counts, byte volume
- Demo dataset: KDD Cup 99 (500K records, 41 features)

**Layer 2: Unsupervised Detection (Isolation Forest)**
- Learns normal traffic patterns *without* labels
- Isolation Forest isolates anomalies: unusual port combos, excessive flag rates, protocol mismatches
- Quick detection of novel/unknown attack types

**Layer 3: Supervised Classification (XGBoost)**
- Trained on labeled attacks: Normal, Probe, DoS, U2R (user-to-root), R2L (remote-to-local)
- Severity scoring: 0-100 attack confidence
- Explains: "This connection is 92% DoS because: packet rate 100x normal (-80 points), TCP flags reset 50x (-12 points)"

## 🛠️ Tech Stack
- **Scikit-learn** — Isolation Forest, preprocessing
- **XGBoost** — attack classification
- **SHAP** — explainability
- **Pandas** — feature engineering
- **Streamlit** — dashboard

## 🚀 Getting Started
```bash
git clone https://github.com/Varshini487/intrusion-detection-system
cd intrusion-detection-system
pip install -r requirements.txt
streamlit run app.py
```

## 💡 Use Cases
- Enterprise network security
- ISP/datacenter DDoS detection
- Incident response triage
- Security operations center (SOC) dashboards

## 🎤 Interview Talking Points
1. **Unsupervised + Supervised = defense-in-depth.** Supervised catches known attacks (90%). Unsupervised catches zero-days (novel patterns). Combined: 95%+ detection + adaptation.
2. **Feature engineering beats raw packets.** 10,000 bytes raw packet data is noisy. 41 engineered features (packet counts, flag rates, protocol mismatch) compress signal, reduce noise.
3. **SHAP explanations drive security team action.** Alert says "92% DoS." With SHAP: "src=10.0.0.5, 100K packets/min, TCP-RST flags=95%." Security team now knows: block 10.0.0.5, tune IDS thresholds, alert upstream.
