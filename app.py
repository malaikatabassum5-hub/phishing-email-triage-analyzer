
import streamlit as st
import re
import dns.resolver
import dns.exception
from email.parser import BytesParser
from urllib.parse import urlparse

# PAGE CONFIGURATION
st.set_page_config(
    page_title="Phishing Email Triage Analyzer",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Phishing Email Triage Analyzer")

st.write(
    "A defensive email investigation tool for identifying suspicious indicators."
)


# --------------------------------------------------
# EMAIL ADDRESS DNS CHECKER
# --------------------------------------------------

def check_email_address(email):

    email = email.strip().lower()

    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return {"error": "Invalid email format."}

    domain = email.split("@")[-1]

    def get_records(name, record_type):
        try:
            answers = dns.resolver.resolve(
                name,
                record_type,
                lifetime=4
            )
            return [str(record).strip('"') for record in answers]

        except dns.exception.DNSException:
            return []

    mx_records = get_records(domain, "MX")
    txt_records = get_records(domain, "TXT")
    dmarc_records = get_records(
        f"_dmarc.{domain}",
        "TXT"
    )

    a_records = get_records(domain, "A")
    aaaa_records = get_records(domain, "AAAA")

    has_domain = bool(mx_records or a_records or aaaa_records)

    has_spf = any(
        record.lower().startswith("v=spf1")
        for record in txt_records
    )

    has_dmarc = any(
        record.lower().startswith("v=dmarc1")
        for record in dmarc_records
    )

    findings = []
    score = 0

    if not has_domain:
        findings.append("No domain DNS records were found.")
        score += 50

    if not mx_records:
        findings.append("No MX records found.")
        score += 10

    if not has_spf:
        findings.append("No SPF record found.")
        score += 15

    if not has_dmarc:
        findings.append("No DMARC record found.")
        score += 15

    score = min(score, 100)

    if score >= 60:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    if not findings:
        findings.append(
            "No configured DNS concerns detected."
        )

    return {
        "domain": domain,
        "score": score,
        "risk": risk,
        "findings": findings
    }


# EMAIL ADDRESS CHECKER INTERFACE

st.header("🔎 Email Address Safety Check")

email_input = st.text_input(
    "Enter an email address",
    placeholder="example@domain.com"
)

if st.button("Analyze Email Address"):

    if email_input.strip():

        result_email = check_email_address(email_input)

        if "error" in result_email:

            st.error(result_email["error"])

        else:

            st.subheader("Address Analysis")

            col1, col2 = st.columns(2)

            col1.metric(
                "Risk Score",
                f'{result_email["score"]}/100'
            )

            col2.metric(
                "Risk Level",
                result_email["risk"]
            )

            st.write(
                "**Domain:**",
                result_email["domain"]
            )

            st.subheader("DNS Findings")

            for finding in result_email["findings"]:
                st.write("•", finding)

            st.info(
                "This checks domain DNS configuration only. "
                "It cannot verify mailbox ownership or prove "
                "that an email address or message is safe."
            )

    else:
        st.warning("Please enter an email address.")


st.divider()


# --------------------------------------------------
# EMAIL FILE ANALYZER
# --------------------------------------------------

st.header("📩 Email File Investigation")

st.write(
    "Upload an .eml file to inspect its headers, URLs and attachments."
)


def analyze_email(file_bytes):

    file_bytes = file_bytes.lstrip()

    msg = BytesParser().parsebytes(file_bytes)

    sender = msg.get("From", "Not available")
    reply_to = msg.get("Reply-To", "Not available")
    subject = msg.get("Subject", "No subject")

    auth_results = msg.get(
        "Authentication-Results",
        "Not available"
    )

    body = ""
    attachments = []

    # EXTRACT EMAIL BODY AND ATTACHMENTS

    for part in msg.walk():

        filename = part.get_filename()

        if filename:
            attachments.append(filename)

        elif part.get_content_type() == "text/plain":

            try:
                body += part.get_content()

            except Exception:
                pass

    # EXTRACT URLS

    email_text = file_bytes.decode(
        "utf-8",
        errors="ignore"
    )

    urls = re.findall(
        r'https?://[^\s<>"]+',
        email_text
    )

    findings = []
    score = 0

    # CHECK REPLY-TO

    if (
        reply_to != "Not available"
        and reply_to.lower() != sender.lower()
    ):

        findings.append(
            "Reply-To differs from the displayed sender."
        )

        score += 15

    # CHECK AUTHENTICATION RESULTS

    if "spf=fail" in auth_results.lower():

        findings.append(
            "SPF authentication failure reported."
        )

        score += 20

    if "dkim=fail" in auth_results.lower():

        findings.append(
            "DKIM authentication failure reported."
        )

        score += 20

    if "dmarc=fail" in auth_results.lower():

        findings.append(
            "DMARC authentication failure reported."
        )

        score += 20

    # CHECK URLS

    for url in urls:

        domain = urlparse(url).hostname or ""

        if re.match(
            r'\d{1,3}(\.\d{1,3}){3}',
            domain
        ):

            findings.append(
                "A URL uses an IP address instead of a domain."
            )

            score += 15

    if not findings:

        findings.append(
            "No configured suspicious indicators were detected."
        )

    score = min(score, 100)

    # RISK CLASSIFICATION

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


# UPLOAD EMAIL FILE

uploaded_file = st.file_uploader(
    "Upload an email file (.eml)",
    type=["eml"]
)


if uploaded_file:

    try:

        result = analyze_email(
            uploaded_file.getvalue()
        )

        st.subheader("Investigation Results")

        col1, col2 = st.columns(2)

        col1.metric(
            "Risk Score",
            f'{result["score"]}/100'
        )

        col2.metric(
            "Risk Level",
            result["risk"]
        )

        st.write("**Subject:**", result["subject"])
        st.write("**Sender:**", result["sender"])
        st.write("**Reply-To:**", result["reply_to"])

        # GENERATE REPORT

        report = f"""
PHISHING EMAIL INVESTIGATION REPORT
==================================

Subject: {result["subject"]}
Sender: {result["sender"]}
Reply-To: {result["reply_to"]}

Risk Score: {result["score"]}/100
Risk Level: {result["risk"]}

SECURITY FINDINGS
-----------------
{chr(10).join(result["findings"])}

URLS FOUND
----------
{chr(10).join(result["urls"]) if result["urls"] else "No URLs found."}

ATTACHMENTS
-----------
{chr(10).join(result["attachments"]) if result["attachments"] else "No attachments found."}

Note: This is an educational triage report.
It does not guarantee that an email is safe.
"""

        # DOWNLOAD REPORT

        st.download_button(
            label="📥 Download Investigation Report",
            data=report,
            file_name="email_investigation_report.txt",
            mime="text/plain"
        )

        # SECURITY FINDINGS

        st.subheader("Security Findings")

        for finding in result["findings"]:
            st.write("•", finding)

        # URL RESULTS

        st.subheader("URLs Found")

        if result["urls"]:

            for url in result["urls"]:
                st.code(url)

        else:
            st.write("No URLs found.")

        # ATTACHMENT RESULTS

        st.subheader("Attachment Names")

        if result["attachments"]:

            for filename in result["attachments"]:
                st.write("📎", filename)

        else:
            st.write("No attachments found.")

        # SAFETY WARNING

        st.warning(
            "This is a basic educational triage tool. "
            "A low score does not guarantee an email is safe. "
            "Attachments are listed but never executed."
        )

    except Exception:

        st.error(
            "Unable to parse this email file. "
            "Please check the .eml format."
        )
