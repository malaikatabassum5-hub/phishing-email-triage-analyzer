
import streamlit as st
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

st.set_page_config(
    page_title="Phishing Email Triage Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Phishing Email Triage Analyzer")
st.write("A defensive email investigation tool for identifying suspicious indicators.")

def analyze_email(file_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(file_bytes)

    sender = msg.get("From", "Not available")
    reply_to = msg.get("Reply-To", "Not available")
    subject = msg.get("Subject", "No subject")
    auth_results = msg.get("Authentication-Results", "Not available")

    body = ""
    attachments = []

    for part in msg.walk():
        filename = part.get_filename()

        if filename:
            attachments.append(filename)
        elif part.get_content_type() == "text/plain":
            try:
                body += part.get_content()
            except Exception:
                pass

    urls = re.findall(r'https?://[^\s<>"]+', body)

    findings = []
    score = 0

    if reply_to != "Not available" and reply_to.lower() != sender.lower():
        findings.append("Reply-To differs from the displayed sender.")
        score += 15

    if "spf=fail" in auth_results.lower():
        findings.append("SPF authentication failure reported.")
        score += 20

    if "dkim=fail" in auth_results.lower():
        findings.append("DKIM authentication failure reported.")
        score += 20

    if "dmarc=fail" in auth_results.lower():
        findings.append("DMARC authentication failure reported.")
        score += 20

    for url in urls:
        domain = urlparse(url).hostname or ""
        if re.match(r'\d{1,3}(\.\d{1,3}){3}', domain):
            findings.append("A URL uses an IP address instead of a domain.")
            score += 15

    if not findings:
        findings.append("No configured suspicious indicators were detected.")

    score = min(score, 100)

    if score >= 60:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    return {
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "urls": urls,
        "attachments": attachments,
        "findings": findings,
        "score": score,
        "risk": risk
    }

uploaded_file = st.file_uploader(
    "Upload an email file (.eml)",
    type=["eml"]
)

if uploaded_file:
    try:
        result = analyze_email(uploaded_file.getvalue())

        st.subheader("Investigation Results")

        col1, col2 = st.columns(2)
        col1.metric("Risk Score", f'{result["score"]}/100')
        col2.metric("Risk Level", result["risk"])

        st.write("**Subject:**", result["subject"])
        st.write("**Sender:**", result["sender"])
        st.write("**Reply-To:**", result["reply_to"])

        st.subheader("Security Findings")
        for finding in result["findings"]:
            st.write("•", finding)

        st.subheader("URLs Found")
        for url in result["urls"]:
            st.code(url)

        st.subheader("Attachment Names")
        for filename in result["attachments"]:
            st.write("📎", filename)

        st.warning(
            "This is a basic educational triage tool. "
            "A low score does not guarantee an email is safe. "
            "Attachments are listed but never executed."
        )

    except Exception:
        st.error("Unable to parse this email file. Please check the .eml format.")
