
<div align="center">

# PHISHING EMAIL
# TRIAGE ANALYZER

**Email Investigation · Domain Security · Defensive Cybersecurity**

A Python-based tool for examining suspicious emails and identifying basic domain security configuration issues.

<br>

[Live Demo](https://phishing-email-triage-analyzer-3eht2cclzxahahghphw4b4.streamlit.app/) · [GitHub Repository](https://github.com/malaikatabassum5-hub/phishing-email-triage-analyzer)

</div>

---

## Overview

Phishing emails remain a common cybersecurity threat. This project explores how basic email analysis and domain security checks can help identify suspicious indicators.

The application provides two separate analysis options: an email address DNS check and an `.eml` file investigation.

## Application Preview

![Application Screenshot](email%20analyzer.png)

## Features

### 01 — Email Address Analysis

Examines the domain associated with an entered email address.

- DNS record lookup (A, AAAA and MX)
- SPF record detection
- DMARC record detection
- Domain configuration risk score
- Findings and configuration warnings

### 02 — Email File Investigation

Allows users to upload an `.eml` file and examine its contents.

- Sender and Reply-To extraction
- Subject identification
- SPF, DKIM and DMARC failure indicators
- URL extraction
- IP-based URL identification
- Attachment filename extraction
- Heuristic risk scoring
- Downloadable investigation report

## Technology

| Component | Technology |
|---|---|
| Language | Python |
| Interface | Streamlit |
| DNS Analysis | dnspython |
| Email Parsing | Python Email Parser |
| Pattern Detection | Regular Expressions |

## Running Locally

```bash
git clone https://github.com/malaikatabassum5-hub/phishing-email-triage-analyzer.git

cd phishing-email-triage-analyzer

pip install -r requirements.txt

streamlit run app.py
```

## Important Limitations

This project is designed for educational and defensive analysis.

- DNS checks assess domain configuration, not mailbox existence or ownership.
- A low risk score does not establish that an email address is safe.
- Email authentication results are read from the supplied message headers and are not independently verified.
- Risk scores are based on simple predefined rules, not machine learning.
- Attachments are identified by filename but are not opened or executed.

## Project Focus

Built to develop practical understanding of:

`Email Security` · `DNS` · `SPF` · `DKIM` · `DMARC` · `Phishing Investigation`


## In Simple Terms

This is a basic email security analysis tool that I built using Python and Streamlit. It has two main functions: checking an email domain's DNS security configuration and analyzing uploaded `.eml` files for suspicious indicators. It uses simple predefined rules to highlight potential concerns and generate a risk score. The purpose is to make basic email investigation easier while learning practical email security concepts. It is an educational project, not a complete phishing detection or email verification system.


---

<div align="center">

**A hands-on cybersecurity learning project**

</div>
