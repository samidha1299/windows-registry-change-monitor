# Windows Registry Change Monitoring System 
**Automated Endpoint Integrity Auditing & Persistence Detection Toolkit**

## 📌 Project Overview
The **Windows Registry Change Monitoring System** is a host-based security agent designed to safeguard the Windows Registry from malicious tampering and unauthorized configuration shifts. Operating as an **Endpoint Detection and Response (EDR) Simulator**, it baselines critical registry keys, monitors them using a 5-second polling loop, and alerts administrators instantly to any system anomalies.

---

## 📌 Core Features
* **Integrity Baselines:** Inventories critical keys into a structured JSON snapshot map.
* **Persistence Detection:** Tracks unauthorized injections in system autostart (`Run`/`RunOnce`) keys.
* **Defense Evasion Interception:** Detects changes to User Account Control (UAC) privileges.
* **Forensic Archiving:** Generates timestamped alerts and dumps live reports to `Registry_Report.txt'.

---

## 📌 Monitored Registry Paths
The system tracks high-value administrative configuration and startup keys:
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (User Autostart).
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` (User Single-Execution).
* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (System Global Autostart).
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` (System Single-Execution).
* `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` (UAC Security Policies).

---

## 📌 Tech Stack
* **Language:** Python 3.x
* **Standard Libraries:** `winreg`, `json`, `datetime`, `os`, `time`
* **Verification Utilities:** Command Prompt (Admin), Registry Editor (`regedit`), PowerShell.

---

## 📌 How To Run, Test, and Validate

> ⚠️ **Prerequisite:** You must launch your command-line interface with **Elevated Administrator Privileges**.

### 1. Launch the Security Agent
```cmd
cd D:\Project\Project 2
python registry_monitor.py
