import streamlit as st
import pickle

model = pickle.load(open('model.pkl','rb'))

st.title("Malaysia Banking Phishing Detector")
st.subheader("With Localized Threat Intelligence - FYP2 Alyssa")
st.write("Detect Maybank / HLB / CIMB / TNG Scam Links")

url = st.text_input("Paste URL here:")

if st.button("Check"):
    url_lower = url.lower()
    
    # Legit official domains - MUST BE SAFE
    legit_domains = ['maybank2u.com.my','maybank.com.my','hlb.com.my','hongleong.com.my','cimb.com.my','cimbclicks.com.my','rhb.com.my','publicbank.com.my','tngdigital.com.my']
    
    bank_keywords = ['maybank','maybank2u','hlb','hongleong','cimb','cimbclicks','rhb','bankislam','publicbank','tng','touchngo']
    scam_keywords = ['secure-login','secure-','verify','login-update','account-locked','reactivate','.tk','.ml','.gq','.cf','@','-login','login-']
    
    has_bank = any(k in url_lower for k in bank_keywords)
    has_scam = any(k in url_lower for k in scam_keywords)
    is_legit_domain = any(k in url_lower for k in legit_domains)
    
    length = len(url)
    has_at = 1 if '@' in url else 0
    has_bank_feature = 1 if has_bank else 0

    # LOGIC FIX
    if is_legit_domain and not has_scam:
        st.success("✅ SAFE - Official Bank Domain")
        st.write("This is a legitimate Malaysia bank website")
    elif has_bank and has_scam:
        st.error("🚨 CONFIRMED PHISHING! - Malaysia Bank Scam Pattern Detected")
        st.write(f"Reason: Fake bank name + Suspicious pattern")
    else:
        result = model.predict([[length, has_at, has_bank_feature]])
        if result[0] == 'bad':
            st.error("🚨 BAHAYA! Phishing Detected by Model")
        else:
            st.success("✅ SAFE - Legitimate URL")
    
    st.caption(f"Debug: length={length}, legit={is_legit_domain}, bank={has_bank}, scam={has_scam}")
