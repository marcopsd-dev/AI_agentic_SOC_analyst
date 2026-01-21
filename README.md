# ⚔️ Warne SOC Agent

> **AI‑driven SOC threat hunting and response for Azure environments**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Azure](https://img.shields.io/badge/Azure-Log%20Analytics-0078D4.svg)](https://azure.microsoft.com/)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4-412991.svg)](https://openai.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 📌 Overview

**Warne SOC Agent** is an agentic AI security operations tool designed to improve **threat hunting efficiency** and **response consistency** in Azure environments. Built as a **portfolio project**, it demonstrates how AI can assist SOC teams by translating natural‑language investigations into structured hunts aligned with **MITRE ATT&CK**, while enforcing strong security controls and auditability.

The project emphasizes **secure‑by‑design engineering**, realistic SOC workflows, and cloud‑native telemetry rather than purely theoretical AI use cases.

---

## ✨ Core Capabilities

### 🔍 AI‑Assisted Threat Hunting

* Natural‑language querying of Azure Log Analytics
* AI‑driven analysis of security events and patterns
* Automatic mapping to **MITRE ATT&CK tactics and techniques**
* Confidence‑based severity classification (Low → Critical)

### 🚨 Automated & Guided Response

* Automated device isolation for high‑confidence threats
* Microsoft Defender for Endpoint (MDE) integration
* Configurable response thresholds and safeguards
* Exception handling for bulk or sensitive actions

### 🔐 Identity, Access & Trust

* Role‑based access control (**Analyst, SOC Lead, Admin**)
* Multi‑factor authentication (TOTP)
* Session tokens with expiration and invalidation
* Encrypted storage for sensitive user data

### 📊 SOC Operations & Visibility

* Persistent logging and full audit trails
* Email notifications for alerts and response actions
* Rate limiting and abuse prevention
* System and application‑level testing hooks

---

## 🚀 Getting Started

### Prerequisites

```bash
Azure subscription (Log Analytics workspace)
OpenAI API key
Optional:

* SMTP server for email notifications
```

### Installation

```bash
WORKING ON DESKTOP PACKAGING FOR PRODUCTION DEPLOYMENT :) 
```

### First‑Time Initialization:

On first launch, the setup flow creates the initial administrator:

* Define admin identity
* Receive a one‑time generated password
* Enroll MFA (recommended)
* Enforce password rotation

### Initialization Display: 

<img width="600" height="1000" alt="Untitled design (3)" src="https://github.com/user-attachments/assets/7ff0958b-fc0e-45b6-85c0-2bf5404b3ff8" />

---

## 🧭 Usage Example

**Sample threat hunt query:**

```text
Show failed login attempts from high‑risk geolocations in the last 24 hours
```

The agent will:

1. Interpret intent and required data sources
2. Query Azure Log Analytics
3. Analyze results using AI
4. Map activity to MITRE ATT&CK
5. Recommend or execute response actions

### Query Display:
<img width="2084" height="872" alt="Screenshot 2026-01-12 025745" src="https://github.com/user-attachments/assets/b47736d4-d846-42fc-b02a-10bee22b85e3" />

---

## 🏗️ High‑Level Architecture

```
┌─────────────────┐
│   CLI / UI      │
└────────┬────────┘
         │
┌────────▼───────────────────────────────┐
│ Authentication & Access Control        │
│ (RBAC, MFA, Sessions, Audit Logging)   │
└────────┬───────────────────────────────┘
         │
┌────────▼───────────────────────────────┐
│ SOC Operations Engine                  │
│  • Query Parsing                       │
│  • AI Analysis                         │
│  • MITRE ATT&CK Mapping                │
└────────┬───────────────────────────────┘
         │
┌────────▼───────────────────────────────┐
│ Azure Telemetry & Response Layer       │
│ (Log Analytics, MDE, Guardrails)       │
└───────────────────────────────────────┘
```

---

## 🔐 Security Design Highlights

* **Encryption:** AES‑256‑GCM for sensitive fields
* **Passwords:** bcrypt with salting
* **MFA:** RFC‑compliant TOTP
* **Session Security:** Expiration, revocation, inactivity timeout
* **Abuse Controls:** Rate limiting on response actions
* **Auditability:** Immutable logs of all actions
* **Input Validation:** Protection against SQL and prompt injection

---

## 🗂️ Project Structure

```
warne-soc-agent/
├── auth/                 # Authentication & RBAC
├── database/             # SQLite persistence layer
├── notifications/        # Email & alerting
├── EXECUTOR.py           # Azure & MDE integrations
├── GUARDRAILS.py         # Security controls
├── MODEL_MANAGEMENT.py   # OpenAI integration
├── PROMPT_MANAGEMENT.py  # Prompt engineering
├── _main.py              # Application entry point
└── requirements.txt
```

---

## 🧪 Roadmap

* ✅ Core SOC workflows & AI analysis
* ✅ RBAC, MFA, session security
* 🔄 Web‑based UI
* 🔄 Expanded automated testing
* 📋 Desktop packaging
* 📋 Multi‑cloud & multi‑LLM support

---

## 👤 Author

**Marco Posadas**
Cloud Security Engineer
Chicago, IL

* LinkedIn: [www.linkedin.com/in/marco-posadas](www.linkedin.com/in/marco-posadas)

---

## ⚠️ Disclaimer

This project is for **educational and portfolio purposes only. Warne Security Agent 1.4.1 is not production ready as of right now**. It should be deployed only in environments where you have explicit authorization and after appropriate security review.
