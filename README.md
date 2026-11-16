# 🛡️ Phishing Email Triage Analyzer

A Python-based defensive cybersecurity project designed to inspect email files and identify potentially suspicious indicators.

## 📌 Project Overview

This project explores how a SOC analyst can perform basic email triage by reviewing email headers, URLs, and attachment names.

The tool accepts `.eml` files and presents findings through a simple Streamlit interface.

## ✨ Current Features

- Email header inspection
- Sender and Reply-To comparison
- Basic SPF, DKIM, and DMARC result checks
- URL extraction
- Basic IP-based URL detection
- Attachment filename extraction
- Simple risk scoring
- Investigation findings

## 🧰 Technologies Used

- Python
- Streamlit
- Email Parser
- Regular Expressions

## 📂 Project Structure

```text
phishing-email-triage-analyzer/
│
├── app.py
├── requirements.txt
├── README.md
│
└── samples/
    └── test_email.eml
```

## 🚀 Running the Project

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Start the application:

```bash
streamlit run app.py
```

Upload an `.eml` file to view the analysis results.

## 🎯 Learning Objectives

- Understand phishing email indicators.
- Explore email authentication concepts.
- Practise basic email investigation.
- Understand introductory SOC triage workflows.
- Learn Python-based security automation.

  ## Application Screenshot

![Phishing Email Triage Analyzer](phishing-analysis-results.png)

## 🔐 Safety & Limitations

This project is intended for educational and defensive security purposes.

- Uses fictional test email data.
- Does not execute attachments.
- Does not guarantee that an email is safe.
- Risk scores are basic indicators, not definitive verdicts.
- Does not currently perform live threat-intelligence checks or machine-learning classification.

## 👩‍💻 Author

**Malaika Tabassum**

Cybersecurity Student | Aspiring SOC Analyst | Blue Team Enthusiast
