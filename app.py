import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import xgboost as xgb
import matplotlib.pyplot as plt
import seaborn as sns

st.set_page_config(page_title="🔐 Intrusion Detection System", layout="wide")
st.title("🔐 Network Intrusion Detection System")
st.markdown("Detect port scans, brute force, DDoS, and lateral movement attacks in real time.")

# Simulated network traffic dataset
@st.cache_data
def load_network_data():
    np.random.seed(42)
    n_normal = 4500
    n_attack = 500
    
    normal = pd.DataFrame({
        "src_port": np.random.randint(1024, 65535, n_normal),
        "dst_port": np.random.choice([80, 443, 22, 25, 53], n_normal),
        "protocol": np.random.choice(["TCP", "UDP"], n_normal),
        "packet_rate": np.random.exponential(10, n_normal),
        "byte_volume": np.random.exponential(1000, n_normal),
        "duration": np.random.exponential(5, n_normal),
        "tcp_flags_syn": np.random.exponential(2, n_normal),
        "tcp_flags_ack": np.random.exponential(3, n_normal),
        "tcp_flags_rst": np.random.exponential(0.5, n_normal),
        "attack": "Normal"
    })
    
    attack = pd.DataFrame({
        "src_port": np.random.randint(1024, 65535, n_attack),
        "dst_port": np.random.choice([139, 445, 21, 23], n_attack),  # suspicious ports
        "protocol": np.random.choice(["TCP", "UDP"], n_attack),
        "packet_rate": np.random.exponential(100, n_attack),  # way higher
        "byte_volume": np.random.exponential(5000, n_attack),
        "duration": np.random.exponential(20, n_attack),
        "tcp_flags_syn": np.random.exponential(20, n_attack),
        "tcp_flags_ack": np.random.exponential(5, n_attack),
        "tcp_flags_rst": np.random.exponential(50, n_attack),  # unusual
        "attack": np.random.choice(["DoS", "Probe", "U2R", "R2L"], n_attack)
    })
    
    return pd.concat([normal, attack]).sample(frac=1).reset_index(drop=True)

df = load_network_data()

tab1, tab2, tab3, tab4 = st.tabs(["📊 Data Overview", "🤖 Unsupervised (Isolation Forest)", "🎯 Supervised (XGBoost)", "🚨 Real-time Detection"])

with tab1:
    st.subheader("Network Traffic Dataset")
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Packets", len(df))
    col2.metric("Normal", (df.attack == "Normal").sum())
    col3.metric("Attacks", (df.attack != "Normal").sum())
    
    st.dataframe(df.head(20), use_container_width=True)
    
    fig, ax = plt.subplots(1, 2, figsize=(12, 4))
    df.attack.value_counts().plot(kind="bar", ax=ax[0], color=["green","red","orange","yellow","purple"])
    ax[0].set_title("Attack Type Distribution")
    ax[0].set_ylabel("Count")
    
    df[df.attack == "Normal"]["packet_rate"].hist(bins=50, ax=ax[1], alpha=0.5, label="Normal", color="green")
    df[df.attack != "Normal"]["packet_rate"].hist(bins=50, ax=ax[1], alpha=0.5, label="Attack", color="red")
    ax[1].set_title("Packet Rate: Normal vs Attack")
    ax[1].legend()
    st.pyplot(fig)

with tab2:
    st.subheader("Unsupervised: Isolation Forest (Anomaly Detection)")
    st.markdown("Learns normal patterns *without labels*. Detects novel/unknown attacks.")
    
    if st.button("🔍 Train Isolation Forest"):
        X = df[["src_port", "packet_rate", "byte_volume", "duration", "tcp_flags_syn", "tcp_flags_rst"]]
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        iso_forest = IsolationForest(contamination=0.1, random_state=42)
        predictions = iso_forest.fit_predict(X_scaled)
        scores = iso_forest.score_samples(X_scaled)
        
        df["anomaly_score"] = scores
        anomalies = (predictions == -1).sum()
        st.success(f"✅ Isolation Forest detected {anomalies} anomalies ({anomalies/len(df)*100:.1f}%)")
        
        fig, ax = plt.subplots()
        ax.hist(scores[predictions == 1], bins=50, alpha=0.5, label="Normal", color="green")
        ax.hist(scores[predictions == -1], bins=50, alpha=0.5, label="Anomaly", color="red")
        ax.set_title("Anomaly Scores Distribution")
        ax.legend()
        st.pyplot(fig)
        
        st.session_state["iso_forest"] = iso_forest
        st.session_state["scaler"] = scaler

with tab3:
    st.subheader("Supervised: XGBoost (Attack Classification)")
    st.markdown("Trained on labeled attacks. Classifies attack *type* + severity.")
    
    if st.button("🎯 Train XGBoost Classifier"):
        le = LabelEncoder()
        df_enc = df.copy()
        df_enc["protocol"] = le.fit_transform(df_enc["protocol"])
        df_enc["attack_encoded"] = le.fit_transform(df_enc["attack"])
        
        X = df_enc[["src_port", "dst_port", "protocol", "packet_rate", "byte_volume", "duration", 
                    "tcp_flags_syn", "tcp_flags_ack", "tcp_flags_rst"]]
        y = df_enc["attack_encoded"]
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        model = xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=42)
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        
        accuracy = (y_pred == y_test).sum() / len(y_test)
        st.success(f"✅ XGBoost trained! Accuracy: {accuracy:.1%}")
        st.text(classification_report(y_test, y_pred, target_names=["Normal", "DoS", "Probe", "R2L", "U2R"][:len(np.unique(y))]))
        
        st.session_state["xgb_model"] = model

with tab4:
    st.subheader("Real-time Threat Detection")
    
    c1, c2, c3 = st.columns(3)
    src_port = c1.number_input("Source Port", 1024, 65535, 50000)
    dst_port = c2.number_input("Dest Port", 1, 65535, 22)
    pkt_rate = c3.number_input("Packet Rate (pps)", 1.0, 10000.0, 50.0)
    
    c1, c2, c3 = st.columns(3)
    byte_vol = c1.number_input("Byte Volume (KB/s)", 1.0, 50000.0, 100.0)
    tcp_syn = c2.number_input("TCP SYN Flags", 0, 10000, 5)
    tcp_rst = c3.number_input("TCP RST Flags", 0, 10000, 2)
    
    if st.button("🚨 Analyze Packet") and "xgb_model" in st.session_state:
        inp = np.array([[src_port, dst_port, 0, pkt_rate, byte_vol, 10, tcp_syn, 0, tcp_rst]])
        risk_score = st.session_state["xgb_model"].predict_proba(inp)[0].max() * 100
        
        if risk_score > 70:
            st.error(f"🚨 HIGH THREAT: {risk_score:.0f}% confidence")
            st.markdown("**Recommended Actions:**")
            st.write("- Block source IP immediately")
            st.write("- Escalate to security team")
            st.write("- Review firewall logs for pattern")
        elif risk_score > 40:
            st.warning(f"⚠️ MEDIUM THREAT: {risk_score:.0f}% confidence")
            st.write("Monitor connection. Log for analysis.")
        else:
            st.success(f"✅ LOW THREAT: {risk_score:.0f}% confidence")

st.markdown("---")
st.markdown("**Stack:** Isolation Forest · XGBoost · SHAP · Scikit-learn · Pandas")
