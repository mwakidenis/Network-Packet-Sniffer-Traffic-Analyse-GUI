# 🕵️‍♂️ Network-Packet-Sniffer-Traffic-Analyse-GUI

Captures &amp; Analyses live network traffic in real time to detect suspicious activities using rule-based, MITRE-mapped, and machine-learning techniques.

## 📸 Screenshots

![screenshot 1](https://github.com/SyedShaheerHussain/Network-Packet-Sniffer-Traffic-Analyse-GUI/blob/adfc26333e9620128a1241615a3514c18f0e089b/network-sniffer/screenshots/Screenshot%20(57).png)

![screenshot 2](https://github.com/SyedShaheerHussain/Network-Packet-Sniffer-Traffic-Analyse-GUI/blob/adfc26333e9620128a1241615a3514c18f0e089b/network-sniffer/screenshots/Screenshot%20(58).png)

![screenshot 3](https://github.com/SyedShaheerHussain/Network-Packet-Sniffer-Traffic-Analyse-GUI/blob/adfc26333e9620128a1241615a3514c18f0e089b/network-sniffer/screenshots/Screenshot%20(59).png)

# 🛡️ Enterprise Network Sniffer IDS (Intrusion Detection System)

**Developed by:** © 2026 **Syed Shaheer Hussain**

## 📌 Project Introduction

The **Enterprise Network Sniffer IDS** is a Python‑based enterprise‑grade **network traffic monitoring and intrusion detection system**. It captures live network packets, analyzes them in real time, detects suspicious or malicious behavior (such as port scanning, flooding, abnormal traffic patterns), and generates **forensic‑ready PDF reports**.

>[!caution]
> This project is designed for **learning, research, academic (FYP), and defensive security simulation purposes**.

## 🎯 Mission & Vision

### 🎯 Mission

To provide a **practical, understandable, and extensible IDS solution** that helps students and security enthusiasts understand how real‑world network monitoring and intrusion detection systems work.

### 🌍 Vision

To evolve this system into a **full enterprise SOC‑ready IDS/IPS platform** with dashboards, ML‑based detection, and SIEM integration.

## ❓ What is a Network?

A **network** is a collection of devices (computers, servers, routers, switches, IoT devices) connected together to share data and resources.

Examples:

* 🌐 Internet
* 🏢 Office LAN
* ☁️ Cloud infrastructure

## 🔍 What is Network Sniffing?

**Network sniffing** is the process of:

* Capturing network packets
* Inspecting headers & payloads
* Analyzing traffic behavior

### Why Sniffing is Important?

* Detect attacks
* Troubleshoot networks
* Monitor bandwidth
* Forensic investigation

>[!important]
> ⚠️ Sniffing without permission is **illegal**.

## 🛡️ What is an IDS?

An **Intrusion Detection System (IDS)** monitors network traffic and:

* Detects malicious patterns
* Generates alerts
* Logs incidents
* Produces reports

### IDS Types

1. **NIDS** – Network‑based IDS ✅ (This project)
2. HIDS – Host‑based IDS


## 💡 Why This Project Was Made?

✔️ To learn **real‑world cybersecurity**
✔️ To simulate **enterprise IDS behavior**
✔️ To understand **packet‑level attacks**
✔️ To build a **portfolio‑grade security project**
✔️ To prepare for SOC / Blue Team roles


## 🏗️ Project Architecture

```
[ Network Interface ]
        ↓
[ Packet Capture Engine ] (Scapy / PyShark)
        ↓
[ Detection Engine ]
        ↓
[ Event Logger ]
        ↓
[ GUI Dashboard ]
        ↓
[ PDF Report Generator ]

```

## 📂 Folder Structure
```
└── network-sniffer/
    ├── IDS_Report.pdf
    ├── main.py
    ├── requirements.txt
    ├── utils/
    │   ├── logger.py
    │   ├── permissions.py
    │   ├── theme.py
    │   └── __pycache__/
    │       ├── logger.cpython-314.pyc
    │       └── theme.cpython-314.pyc
    ├── screenshots/
    │   ├── Screenshot (57).png
    │   ├── Screenshot (58).png
    │   └── Screenshot (59).png
    ├── gui/
    │   ├── app.py
    │   ├── charts.py
    │   └── __pycache__/
    │       ├── app.cpython-314.pyc
    │       └── charts.cpython-314.pyc
    └── core/
        ├── ids_engine.py
        ├── mitre.py
        ├── ml_detector.py
        ├── pcap_manager.py
        ├── pyshark_sniffer.py
        ├── report.py
        ├── scapy_sniffer.py
        └── __pycache__/
            ├── ids_engine.cpython-314.pyc
            ├── mitre.cpython-314.pyc
            ├── ml_detector.cpython-314.pyc
            ├── pcap_manager.cpython-314.pyc
            ├── pyshark_sniffer.cpython-314.pyc
            ├── report.cpython-314.pyc
            └── scapy_sniffer.cpython-314.pyc

```

## 🧠 Core Concepts Used

* Packet sniffing
* TCP/IP analysis
* Port scan detection
* Behavioral analysis
* Log correlation
* Defensive cybersecurity

## ⚙️ Technologies Used

### 🧑‍💻 Programming Languages

* Python 3.10+

### 📦 Libraries & Tools

* Scapy
* PyShark (Wireshark TShark)
* FPDF (PDF reports)
* PyQt5 / Tkinter (GUI)
* Logging module

### 🖥️ OS Support

* Windows ✅
* Linux ✅


## 🖼️ GUI Features

✔️ Start / Stop Sniffing
✔️ Live event log window
✔️ IDS alerts display
✔️ Generate PDF report
✔️ Clean enterprise layout

## ⚡ Features

1. Real‑time packet capture
2. Port scan detection (T1046)
3. Event logging
4. GUI‑based control
5. Auto PDF reporting
6. Old reports preserved
7. Unicode‑safe PDF generation

## 🔧 Functions Overview

* `start_sniffing()` – Begin packet capture
* `stop_sniffing()` – Stop capture
* `analyze_packet()` – Detect suspicious behavior
* `log_event()` – Save IDS alerts
* `generate_pdf()` – Create forensic report

## 📄 PDF Reporting System

✔️ Each report saved with timestamp
✔️ No old report replaced
✔️ Long lines auto wrapped
✔️ Hex & raw data safe

Example Output:

```
IDS_Report_20260202_154001.pdf

```

## 🚀 Installation Guide (Step‑by‑Step)

### 1️⃣ Install Python

Download from:
👉 [https://www.python.org](https://www.python.org)

✔️ Tick **Add Python to PATH**

### 2️⃣ Install Wireshark (Required)

Download:
👉 [https://www.wireshark.org](https://www.wireshark.org)

✔️ Ensure **TShark** is installed
✔️ Default path:

```
C:\Program Files\Wireshark\tshark.exe

``` 
Or Open Command Prompt

```
where tshark

```
* This cmd tells you the location/path of tshark
* Make sure the wireshark folder assigned in Envoirnment Variable Path

### 3️⃣ Install Project Dependencies

Open CMD in project folder:

```
pip install -r requirements.txt

```

## ▶️ How to Run the Project

### Step 1

```
cd network-sniffer

```

### Step 2

```
python main.py

```

## 🖥️ How to Use (GUI)

1️⃣ Click **Start Sniffing**
2️⃣ Generate traffic (browser, ping, scan)
3️⃣ Watch alerts in GUI
4️⃣ Click **Generate Report**
5️⃣ PDF saved in `IDS_Reports/`

## 🌐 Chrome / Browser Usage

✔️ Open Chrome
✔️ Browse any website
✔️ IDS captures packets automatically

❌ No username/password required
❌ Runs locally on your machine

## 📊 Flow Chart

```
Start
 ↓
Select Interface
 ↓
Capture Packets
 ↓
Analyze Traffic
 ↓
Threat Detected?
 ↓      ↓
Yes     No
 ↓       ↓
Log Event
 ↓
Generate Report
 ↓
End

```

## ⚠️ Cautions

>[!caution]
> * ❌ Do NOT use on public networks
> * ❌ Do NOT sniff without permission
> * ❌ Educational use only

## 📌 Important Notes

>[!important]
> * Requires admin privileges
> * Antivirus may flag sniffing
> * Heavy traffic may slow system

## 📚 What You Will Learn

✔️ Network protocols
✔️ IDS working
✔️ Packet analysis
✔️ Cyber defense mindset
✔️ Python system design

## 📈 Market Value

This project is valuable for:

* SOC Analyst roles
* Blue Team jobs
* Cybersecurity portfolios
* FYP / Thesis

## 🚀 Future Enhancements

* ML‑based anomaly detection
* Web dashboard
* SIEM integration
* Email alerts
* Cloud monitoring
* IPS (auto blocking)

## 📜 Disclaimer

>[!important]
> This software is provided **for educational and research purposes only**. The developer is **not responsible for misuse**.

## 📝 Copyright

© 2026 **Syed Shaheer Hussain**
All rights reserved.

## ⭐ Final Note

>[!note]
> This project demonstrates **real enterprise cybersecurity concepts** in a simple, understandable, and extensible way. It is ideal for students, researchers, and security enthusiasts.

🛡️ *Learn. Detect. Defend.*
