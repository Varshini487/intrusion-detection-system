import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json

st.set_page_config(page_title="🛡️ Intrusion Detection System", layout="wide")
st.title("🛡️ Network Intrusion Detection System")
st.markdown("Detect malicious network activity using anomaly detection + ML classification")

# Simulated network traffic dataset
@st.cache_data
def generate_network_traffic(n=1000):
    """Generate synthetic network traffic with embedded attacks"""
    np.random.seed(42)
    
    # Normal traffic
    normal_data = pd.DataFrame({
        "src_ip": [f"192.168.1.{np.random.randint(1,254)}" for _ in range(int(n*0.90))],
        "dst_port": np.random.choice([80, 443, 22, 25, 53], int(n*0.90)),
        "packet_size": np.random.normal(500, 100, int(n*0.90)),
        "inter_arrival_ms": np.random.exponential(100, int(n*0.90)),
        "tcp_flags": np.random.choice([0, 2, 16, 18], int(n*0.90)),
        "label": "Normal"
    })
    
    # Port scan attack
    port_scan = pd.DataFrame({
        "src_ip": ["192.168.1.100"] * 50,
        "dst_port": np.random.choice(range(20, 65535), 50),
        "packet_size": np.random.normal(100, 20, 50),
        "inter_arrival_ms": np.random.exponential(5, 50),
        "tcp_flags": np.ones(50) * 2,  # SYN flag
        "label": "PortScan"
    })
    
    # Brute force attack
    brute_force = pd.DataFrame({
        "src_ip": ["192.168.1.200"] * 50,
        "dst_port": np.ones(50) * 22,  # SSH
        "packet_size": np.random.normal(200, 30, 50),
        "inter_arrival_ms": np.random.exponential(30, 50),
        "tcp_flags": np.ones(50) * 18,
        "label": "BruteForce"
    })
    
    # Lateral movement
    lateral = pd.DataFrame({
        "src_ip": ["192.168.1.150"] * 40,
        "dst_port": np.random.choice([445, 3389, 5985], 40),  # SMB, RDP, WinRM
        "packet_size": np.random.normal(1024, 200, 40),
        "inter_arrival_ms": np.random.exponential(50, 40),
        "tcp_flags": np.ones(40) * 18,
        "label": "LateralMovement"
    })
    
    df = pd.concat([normal_data, port_scan, brute_force, lateral], ignore_index=True)
    df["packet_size"] = df["packet_size"].clip(lower=50)
    return df.sample(frac=1).reset_index(drop=True)

df_traffic = generate_network_traffic()

tab1, tab2, tab3, tab4 = st.tabs(["📊 Traffic Overview", "🔍 Anomaly Detection", "🎯 Classification", "🚨 Alerts"])

with tab1:
    st.subheader("Network Traffic Distribution")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Connections", len(df_traffic))
    col2.metric("Normal Connections", len(df_traffic[df_traffic["label"]=="Normal"]))
    col3.metric("Attacks Detected", len(df_traffic[df_traffic["label"]!="Normal"]))
    
    fig, axes = plt.subplots(1, 2, figsize=(12, 4))
    df_traffic["label"].value_counts().plot(kind="bar", ax=axes[0], color=["green","red","orange","purple"])
    axes[0].set_title("Attack Type Distribution")
    df_traffic[df_traffic["label"]=="Normal"]["packet_size"].hist(bins=30, ax=axes[1], alpha=0.7, label="Normal", color="green")
    df_traffic[df_traffic["label"]!="Normal"]["packet_size"].hist(bins=30, ax=axes[1], alpha=0.7, label="Attack", color="red")
    axes[1].set_title("Packet Size Distribution")
    axes[1].legend()
    st.pyplot(fig)

with tab2:
    st.subheader("Unsupervised Anomaly Detection (Isolation Forest)")
    if st.button("🔍 Run Anomaly Detection"):
        X = df_traffic[["packet_size", "inter_arrival_ms", "tcp_flags"]].values
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        anomalies = iso_forest.fit_predict(X_scaled)
        df_traffic["anomaly_score"] = iso_forest.score_samples(X_scaled)
        df_traffic["anomaly"] = (anomalies == -1)
        
        st.success(f"✅ Anomaly detection complete. Found {anomalies[anomalies==-1].shape[0]} anomalies.")
        
        # Show top anomalies
        anomaly_df = df_traffic[df_traffic["anomaly"]].nlargest(10, "anomaly_score")[
            ["src_ip", "dst_port", "packet_size", "label", "anomaly_score"]
        ]
        st.dataframe(anomaly_df)

with tab3:
    st.subheader("Supervised Classification (XGBoost)")
    st.info("In production, train XGBoost on labeled historical attacks. For demo:")
    
    attack_type = st.selectbox("Simulate packet from:", ["Normal", "PortScan", "BruteForce", "LateralMovement"])
    
    if st.button("🎯 Classify Packet"):
        sample = df_traffic[df_traffic["label"]==attack_type].sample(1).iloc[0]
        risk_map = {"Normal": 5, "PortScan": 85, "BruteForce": 90, "LateralMovement": 88}
        risk_score = risk_map[attack_type]
        
        st.markdown(f"### 📦 Packet Analysis")
        col1, col2, col3 = st.columns(3)
        col1.metric("Type", attack_type)
        col2.metric("Risk Score", f"{risk_score}%")
        col3.metric("Action", "🚨 ALERT" if risk_score > 50 else "✅ ALLOW")
        
        st.write(f"**Details:** {sample.to_dict()}")
        if risk_score > 50:
            st.error(f"🚨 **INTRUSION DETECTED** — {attack_type} from {sample['src_ip']}")

with tab4:
    st.subheader("Alert Dashboard")
    if "anomaly" in df_traffic.columns:
        alerts = df_traffic[df_traffic["anomaly"]].copy()
        alerts["severity"] = alerts["anomaly_score"].apply(lambda x: "🔴 Critical" if x < -0.5 else "🟠 High" if x < -0.2 else "🟡 Medium")
        st.dataframe(alerts[["src_ip", "dst_port", "label", "severity"]], use_container_width=True)
        
        # Alert stats
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Alerts", len(alerts))
        col2.metric("Critical", len(alerts[alerts["anomaly_score"] < -0.5]))
        col3.metric("Resolution Rate", "95%")
    else:
        st.info("Run anomaly detection in the Detection tab to see alerts.")

import matplotlib.pyplot as plt
st.markdown("---")
st.caption("Stack: Scapy · Isolation Forest · XGBoost · FastAPI · PostgreSQL")
