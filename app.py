import streamlit as st
import pandas as pd
import re
from sklearn.ensemble import RandomForestClassifier

st.set_page_config(page_title="MY Banking Phishing Detector", page_icon="🇲🇾", layout="centered")

# --- CSS cantik ---
st.markdown("""
<style>
.big-title { font-size:36px; font-weight:700; color:#0d2a54; }
.card { background:white; padding:20px; border-radius:15px; box-shadow:0 4px 12px rgba(0,0,0,0.1); margin-top:15px; }
.safe { background:#e6f4ea; border-left:6px solid #1e8e3e; padding:15px; border-radius:10px; }
.phish { background:#fce8e6; border-left:6px solid #d93025; padding:15px; border-radius:10px; }
</style>
""", unsafe_allow_html=True)

def extract_features(url):
    return [
        len(url),
        1 if "@" in url else 0,
        url.count("."),
        url.count("-"),
        1 if "https" in url else 0,
        len(url.split("/")),
        1 if url.count("//") > 1 else 0,
        1 if any(c.isdigit() for c in url) else 0,
    ]

@st.cache_resource
def load_model():
    df = pd.read_csv("dataset.csv")
    X = [extract_features(str(u)) for u in df['url']]
    y = df['label'].tolist()
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    return model

model = load_model()

WHITELIST = ["maybank2u.com.my","hlb.com.my","cimbclicks.com.my","rhb.com.my","publicbank.com.my","tngdigital.com.my","bankislam.com.my"]

st.markdown('<div class="big-title">🇲🇾 MY Banking Phishing Detector</div>', unsafe_allow_html=True)
st.caption("Hybrid 3-Layer Protection: Whitelist + Threat Intel + ML | FYP2 - Alyssa")

st.markdown("---")
url_input = st.text_input("🔗 Paste URL here:", placeholder="https://...")

if st.button("🔍 Analyze", type="primary"):
    if not url_input:
        st.warning("Sila masukkan URL dulu")
    else:
        url_lower = url_input.lower().strip()
        
        # LAYER 1
        if any(w in url_lower for w in WHITELIST):
            if not any(x in url_lower for x in [".tk",".ml",".ga",".cf",".gq","secure-login","verify-account"]) and not re.search(r'\d+\.\d+\.\d+\.\d+', url_input):
                st.markdown(f'<div class="safe"><b>✅ SAFE</b><br>Official Bank - Whitelisted<br><small>Layer: Whitelist | Confidence: 99%</small></div>', unsafe_allow_html=True)
                st.balloons()
                st.stop()
        
        # LAYER 2
        scam_tlds = [".tk",".ml",".ga",".cf",".gq"]
        bank_kw = ["maybank","hlb","cimb","rhb","tng","publicbank"]
        scam_kw = ["secure-login","verify","reactivate","secure"]
        is_scam_tld = any(t in url_lower for t in scam_tlds)
        is_bank = any(b in url_lower for b in bank_kw)
        is_scam_kw = any(k in url_lower for k in scam_kw)
        is_ip = bool(re.search(r'\d+\.\d+\.\d+\.\d+', url_input))
        
        if (is_scam_tld and is_bank) or (is_ip and is_bank) or (is_bank and is_scam_kw):
            st.markdown(f'<div class="phish"><b>🚨 CONFIRMED PHISHING</b><br>Threat Intel Detected<br><small>IP: {is_ip} | ScamTLD: {is_scam_tld} | ScamKeyword: {is_scam_kw}</small></div>', unsafe_allow_html=True)
            st.stop()
        
        # LAYER 3
        features = extract_features(url_input)
        pred = model.predict([features])[0]
        prob = model.predict_proba([features])[0].max() * 100
        
        if pred == 1:
            st.markdown(f'<div class="phish"><b>🚨 PHISHING DETECTED (ML)</b><br>Confidence: {prob:.1f}%<br><small>Layer: Machine Learning</small></div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="safe"><b>✅ SAFE (ML)</b><br>Confidence: {prob:.1f}%<br><small>Layer: Machine Learning</small></div>', unsafe_allow_html=True)
        
        with st.expander("Lihat Feature Analysis"):
            st.json({"length":features[0], "has_@":features[1], "dots":features[2], "has_ip_pattern":is_ip})

st.markdown("---")
st.caption("© 2026 FYP2 - Phishing URL Detection System")
