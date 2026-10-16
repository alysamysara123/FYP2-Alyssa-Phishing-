import streamlit as st
import pickle

model = pickle.load(open('model.pkl','rb'))

st.title("Malaysia Phishing Detector - Alyssa FYP2")
st.write("Cek link Maybank / TNG scam")

url = st.text_input("Paste URL sini:")

if st.button("Check"):
    # Rule tambahan untuk detect scam Malaysia
    scam_keywords = ['secure-login', 'secure', 'verify', '.tk', '.ml', '.gq', 'maybank2u-', 'login-update']

    is_scam_keyword = any(k in url.lower() for k in scam_keywords)

    length = len(url)
    has_at = 1 if '@' in url else 0
    has_maybank = 1 if 'maybank' in url.lower() or 'tng' in url.lower() else 0

    if is_scam_keyword:
        st.error("🚨 BAHAYA! Ini Phishing / Scam!")
    else:
        result = model.predict([[length, has_at, has_maybank]])
        if result[0] == 'bad':
            st.error("🚨 BAHAYA! Ini Phishing / Scam!")
        else:
            st.success("✅ Selamat, link legit")
