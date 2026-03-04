import streamlit as st
import pickle
import re
import pandas as pd
import os
import matplotlib.pyplot as plt

# -------------------------------
# 1️⃣ PAGE CONFIG
# -------------------------------
st.set_page_config(
    page_title="Cyber Shield - Phishing Detection",
    page_icon="🛡️",
    layout="wide"
)

# -------------------------------
# 2️⃣ CYBERSECURITY DARK THEME
# -------------------------------
st.markdown("""
<style>

/* Main Background */
.stApp {
    background-color: #0f1117;
    color: #00ffcc;
}

/* Title */
h1 {
    text-align: center;
    color: #00ffcc;
    font-weight: bold;
}

/* Text Area */
textarea {
    background-color: #1a1d25 !important;
    color: #00ffcc !important;
    border-radius: 8px !important;
    border: 1px solid #00ffcc !important;
}

/* File Uploader */
[data-testid="stFileUploader"] {
    background-color: #1a1d25;
    padding: 10px;
    border-radius: 10px;
    border: 1px solid #00ffcc;
}

/* Buttons */
.stButton>button {
    background: linear-gradient(90deg, #00ffcc, #0099ff);
    color: black;
    font-weight: bold;
    border-radius: 10px;
    height: 3em;
    width: 100%;
    transition: 0.3s;
}

.stButton>button:hover {
    background: linear-gradient(90deg, #ff004f, #ff9900);
    color: white;
    transform: scale(1.05);
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #111827;
    color: #00ffcc;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    background-color: #1a1d25;
    color: #00ffcc;
}

/* Progress Bar */
.stProgress > div > div > div {
    background-color: #00ffcc;
}

</style>
""", unsafe_allow_html=True)

# -------------------------------
# 3️⃣ LOAD MODEL
# -------------------------------
model = pickle.load(open("phishing_model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

# -------------------------------
# 4️⃣ HISTORY SETUP
# -------------------------------
HISTORY_FILE = "scan_history.csv"

if os.path.exists(HISTORY_FILE):
    history_df = pd.read_csv(HISTORY_FILE)
else:
    history_df = pd.DataFrame(columns=["Preview", "Prediction", "Confidence"])

# -------------------------------
# 5️⃣ SUSPICIOUS KEYWORDS
# -------------------------------
suspicious_words = [
    "urgent", "verify", "click", "password",
    "bank", "account", "login", "limited",
    "update", "confirm"
]

# -------------------------------
# 6️⃣ SIDEBAR ANALYTICS
# -------------------------------
st.sidebar.title("📊 Threat Analytics")

total_scans = len(history_df)
phishing_count = len(history_df[history_df["Prediction"] == "Phishing"])
legit_count = len(history_df[history_df["Prediction"] == "Legitimate"])

st.sidebar.write(f"Total Emails Scanned: {total_scans}")
st.sidebar.write(f"Phishing Detected: {phishing_count}")
st.sidebar.write(f"Legitimate Emails: {legit_count}")

if total_scans > 0:
    plt.style.use("dark_background")
    fig = plt.figure()
    plt.pie(
        [phishing_count, legit_count],
        labels=["Phishing", "Legitimate"],
        autopct="%1.1f%%"
    )
    plt.title("Threat Distribution")
    st.sidebar.pyplot(fig)

# -------------------------------
# 7️⃣ MAIN HEADER
# -------------------------------
st.markdown("<h1>🛡️ CYBER SHIELD - Email Threat Detection</h1>", unsafe_allow_html=True)
st.markdown("### 🔐 Real-Time AI Powered Security Scanner")

st.markdown("""
<style>
@keyframes blink {
  50% { opacity: 0; }
}
.blink {
  animation: blink 1s step-start infinite;
}
</style>
<h4>System Status: <span class="blink">ACTIVE</span></h4>
""", unsafe_allow_html=True)

# -------------------------------
# 8️⃣ MAIN LAYOUT
# -------------------------------
col1, col2 = st.columns(2)

with col1:
    st.write("### 📩 Email Input")

    email_text = st.text_area("", height=250)
    uploaded_file = st.file_uploader(
        "📂 Upload Email File (.txt or .eml)",
        type=["txt", "eml"]
    )

    if st.button("🔍 Analyze Email"):

        if uploaded_file is not None:
            email_text = uploaded_file.read().decode("utf-8", errors="ignore")

        if email_text.strip() == "":
            st.warning("Please enter email content or upload a file.")
        else:
            with st.spinner("Scanning for threats..."):

                email_vector = vectorizer.transform([email_text])
                prediction = model.predict(email_vector)
                probability = model.predict_proba(email_vector)

                confidence = round(max(probability[0]) * 100, 2)
                st.progress(int(confidence))

                # -----------------------
                # THREAT REPORT PANEL
                # -----------------------
                st.markdown("### 🖥️ Threat Analysis Report")

                st.markdown("""
                <div style='background-color:#1a1d25;
                            padding:15px;
                            border-radius:10px;
                            border:1px solid #00ffcc;'>
                """, unsafe_allow_html=True)

                if prediction[0] == 1:
                    st.markdown("<h3 style='color:#ff4b4b;'>⚠️ PHISHING DETECTED</h3>", unsafe_allow_html=True)
                    result_label = "Phishing"
                else:
                    st.markdown("<h3 style='color:#00ffcc;'>✅ LEGITIMATE EMAIL</h3>", unsafe_allow_html=True)
                    result_label = "Legitimate"

                st.markdown(f"<p>Confidence Level: {confidence}%</p>", unsafe_allow_html=True)

                # Risk Level
                if confidence < 40:
                    st.markdown("<p style='color:#00ffcc;'>🟢 Low Risk</p>", unsafe_allow_html=True)
                elif 40 <= confidence < 70:
                    st.markdown("<p style='color:yellow;'>🟡 Medium Risk</p>", unsafe_allow_html=True)
                else:
                    st.markdown("<p style='color:red;'>🔴 High Risk</p>", unsafe_allow_html=True)

                st.markdown("</div>", unsafe_allow_html=True)

                # -----------------------
                # URL DETECTION
                # -----------------------
                urls = re.findall(r'https?://\S+', email_text)
                if urls:
                    st.write("### 🌐 URLs Found:")
                    for url in urls:
                        st.write("-", url)

                # -----------------------
                # KEYWORD DETECTION
                # -----------------------
                found_words = [
                    word for word in suspicious_words
                    if word in email_text.lower()
                ]

                if found_words:
                    st.write("### ⚠️ Suspicious Keywords Found:")
                    for word in found_words:
                        st.write("-", word)

                # -----------------------
                # SAVE HISTORY
                # -----------------------
                new_entry = pd.DataFrame([{
                    "Preview": email_text[:50] + "...",
                    "Prediction": result_label,
                    "Confidence": confidence
                }])

                history_df = pd.concat([history_df, new_entry], ignore_index=True)
                history_df.to_csv(HISTORY_FILE, index=False)

with col2:
    st.write("### 📜 Scan History")

    if len(history_df) > 0:
        st.dataframe(history_df)
    else:
        st.write("No scans yet.")