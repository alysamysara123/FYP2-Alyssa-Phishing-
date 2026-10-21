import streamlit as st
import pandas as pd
import pickle
import re
from sklearn.ensemble import RandomForestClassifier
import tldextract

# Auto-train model dari dataset.csv
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
    try:
        df = pd.read_csv("dataset.csv")
        X = [extract_features(str(u)) for u in df['url']]
        y = df['label'].tolist()
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X, y)
        return model
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None

model = load_model()

# Whitelist
WHITELIST = ["maybank2u.com.my","hlb.com.my","cimbclicks.com.my","rhb.com.my","publicbank.com.my","tngdigital.com.my","bankislam.com.my","ambank.com.my","bsn.com.my"]

st.title("🇲🇾 MY Banking Phishing Detector")
st.write("Hybrid 3-Layer: Whitelist + Threat Intel + ML")

url_input = st.text_input("Paste URL here:")

if st.button("Analyze"):
    if not url_input:
        st.warning("Please enter URL")
    else:
        url_lower = url_input.lower()
        
        # LAYER 1 - Whitelist
        if any(w in url_lower for w in WHITELIST) and not re.search(r'\d+\.\d+\.\d+\.\d+', url_input):
            if not any(x in url_lower for x in [".tk",".ml",".ga",".cf",".gq","secure-login","verify-account"]):
                st.success("✅ SAFE - Whitelisted Official Bank")
                st.write(f"Layer: Whitelist | Confidence: 99%")
                st.stop()
        
        # LAYER 2 - Threat Intel
        scam_tlds = [".tk",".ml",".ga",".cf",".gq"]
        bank_kw = ["maybank","hlb","cimb","rhb","tng"]
        scam_kw = ["secure-login","verify","reactivate","secure"]
        
        is_scam_tld = any(t in url_lower for t in scam_tlds)
        is_bank = any(b in url_lower for b in bank_kw)
        is_scam_kw = any(k in url_lower for k in scam_kw)
        is_ip = bool(re.search(r'\d+\.\d+\.\d+\.\d+', url_input))
        
        if (is_scam_tld and is_bank) or (is_ip and is_bank) or (is_bank and is_scam_kw):
            st.error("🚨 CONFIRMED PHISHING - Threat Intel")
            st.write(f"Layer: Threat Intel | Reason: IP={is_ip}, ScamTLD={is_scam_tld}, ScamKeyword={is_scam_kw}")
            st.stop()
        
        # LAYER 3 - ML
        if model:
            features = extract_features(url_input)
            pred = model.predict([features])[0]
            prob = model.predict_proba([features])[0].max()
            if pred == 1:
                st.error(f"🚨 PHISHING (ML) - Confidence {prob*100:.1f}%")
            else:
                st.success(f"✅ SAFE (ML) - Confidence {prob*100:.1f}%")
            st.write(f"Layer: ML Model | Features: {features}")
