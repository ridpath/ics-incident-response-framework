<!--
SEO Tags:
ICS incident response, SCADA cybersecurity, OT automation, SOAR for ICS, PLC tampering detection, ICS playbook engine, OT forensics, industrial control system detection, safety system shutdown, critical infrastructure defense
-->

# ICS Incident Response Automation Framework

An open-source, safety first incident response automation system for ICS/SCADA environments.  
Built for operators, analysts, and researchers to **rapidly detect, respond, and contain threats in operational technology (OT) systems.**

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![Status](https://img.shields.io/badge/status-alpha-orange)
![License](https://img.shields.io/badge/license-Research--Only-orange)
![ICS/SCADA](https://img.shields.io/badge/domain-ICS%2FSCADA-critical)
![MITRE ICS ATT&CK](https://img.shields.io/badge/MITRE%20ICS-T0862%20T0886%20T0880%20T0889-orange)

---

## Overview

The **ICS Incident Response Automation Framework** is a tactical tool for handling cyber incidents in OT/ICS networks. Incident response engine tailored for **ICS/SCADA environments**, featuring real-world playbooks, forensic preservation, and safety first automation.
It simulates and executes automated responses to high-impact events like:

- **Unauthorized PLC logic downloads**
- **Historian database tampering**
- **Engineering workstation compromises**
- **SIS (Safety Instrumented System) tampering**

It supports **predefined playbooks**, critical asset protection steps, evidence preservation, operator notification, and interactive statistics — all directly from the command line.

---

## Key Features

| Feature | Description |
|--------|-------------|
| **Playbook-Driven Engine** | Automatically maps security incidents to structured response plans based on severity, type, and triggers. |
| **Safety Shutdown Support** | Supports simulated SIS (Safety Instrumented System) shutdowns and safety interlock engagement procedures. |
| **Forensic Preservation** | Automates evidence collection from PLC memory, engineering workstations, network logs, historian databases, and RAM dumps. |
| **Operator Alerting** | Sends alerts to operations teams via Microsoft Teams and logs notifications in shift logs and control room displays. |
| **Execution Tracking & Stats** | Logs all incident responses, tracks playbook usage, calculates action success rates, and maintains execution history. |
| **Demo & Simulation Mode** | Includes simulated incidents to demonstrate functionality and train analysts without production impact. |
| **Interactive CLI Shell** | Provides a built-in interactive menu to view playbooks, execution logs, statistics, and perform manual incident runs. |
| **Microsoft Teams Integration** | Sends adaptive card alerts for incidents with severity, description, and action summaries in real-time. |
| **STIX & MISP Integration** | Supports STIX 2.1 bundle generation, MISP event creation, IOC correlation, and threat intel caching. |
| **Compliance-Aware Responses** | Includes controls mapped to NIST SP 800-53 and simulates cryptographic operations aligned with FIPS 140-2. |
| **Configurable Response Actions** | Supports multiple response types including isolation, safeguard, logic restore, forensic capture, and shutdown. |
| **Cryptographic Action Signing** | Supports simulation of HSM-signed actions and cryptographic verification patterns for sensitive operations. |

## Microsoft Teams Notification Abilities

| Notification Type         | Description                                                                 |
|---------------------------|-----------------------------------------------------------------------------|
| Adaptive Card Alerts      | Sends structured Teams cards with incident details and context             |
| Real-Time Incident Alerts | Immediately pushes critical or high-severity incidents to Teams channel     |
| Operator Summaries        | Summarizes incidents for shift handovers or situational awareness           |
| Playbook Execution Logs   | Posts summaries of executed response playbooks and action status            |
| Enriched Threat Intel     | Includes correlated STIX/MISP indicators in alerts when applicable          |
| Interactive Acknowledgment (Planned) | Placeholder for future interactive cards (ack, escalate, dismiss)        |



## Getting Started

### Core Dependencies
- requests – REST API interactions
- pycryptodome – AES encryption for secure data handling
- snap7 (optional) – For PLC interaction
- scapy (optional) – For network scanning and packet manipulation
- stix2 & misp-stix (optional) – For threat intel export/integration
- PyYAML – YAML-based configuration support

### Installation

```bash
git clone https://github.com/yourusername/ics-incident-response-framework.git
pip install -r requirements.txt
```

## Tool Usage
Basic Usage
```bash
python3 ics_responder.py --playbooks playbooks.json
```
Demo Mode

Run a full demonstration using a sample incident:
```bash
python3 ics_responder.py --demo
```
Interactive Shell (Default)

Once launched, interactively explore features:

1. View playbooks
2. View execution history
3. View statistics
4. Exit

## Supported CLI Options
Option	Description
- --playbooks	Load response playbooks from a custom JSON file
- --demo	Launch demo mode using a pre-defined test incident
- --help	Show CLI usage and available arguments


## Response Lifecycle

1. **Match Playbook** – Selects a response plan based on incident type and severity.
2. **Execute Actions** – Executes a sequence of actions such as isolation, shutdown, or alerts.
3. **Log & Audit** – Logs each step to ensure traceability and compliance.
4. **Generate Stats** – Tracks playbook usage and action success metrics.


## Supported Response Actions

| Action Type             | Purpose                                                                 |
|-------------------------|-------------------------------------------------------------------------|
| `network_isolation`     | Simulates firewall rules to isolate compromised devices or segments     |
| `process_safeguard`     | Triggers safety measures like safe mode, read-only mode, or SIS actions |
| `forensic_preservation` | Captures PLC memory, workstation snapshots, historian database backups  |
| `operator_alert`        | Notifies engineering or operations team through log/display/email/MSFT Teams |
| `safety_shutdown`       | Activates emergency shutdown using simulated SIS routines               |
| `logic_restore`         | Restores golden images or known-good logic to PLCs                      |


## Short-Term To-Do List (Prioritized)

| Priority | Task                                                   | Notes                                                                 |
|----------|--------------------------------------------------------|-----------------------------------------------------------------------|
| High     | Modularize the codebase                                | Break into CLI, core engine, alerting, integrations, utils, config   |
| High     | Add alerting channels                                  | Add email, Slack, and syslog support for SOC/IR teams                |
| High     | Build REST API (FastAPI preferred)                     | Needed to support frontend UI and third-party integrations           |
| Medium   | Store incidents & execution history in SQLite/Postgres | Replaces flat logging, enables advanced timelines and queries        |
| Medium   | Write a Dockerfile                                     | Enables reproducible builds and simplified deployment                |
| Medium   | Add live IOC correlation (STIX + MISP feeds)           | Pull and cache feeds; correlate in real-time                         |
| Medium   | Build a lightweight web UI                             | React, Dash, or terminal UI; starts with read-only dashboard         |
| Low      | Add basic deception techniques                         | Include tripwire files, canary tokens, and honeypot triggers         |
| Low      | Full STIX 2.1 export support                           | Complete indicator + technique export; currently partial             |
| Low      | Add role-based access control (RBAC)                   | Can start with config-based role mapping or user profiles            |
| Low      | Add Modbus and DNP3 protocol awareness                 | Expand protocol support beyond S7Comm for broader ICS coverage       |

## Longer-Term Enhancements (2025)

| Feature                           | Why It Matters                                                        |
|-----------------------------------|------------------------------------------------------------------------|
| AI-powered event scoring          | Enables baseline anomaly detection and prioritization for small teams |
| MITRE ATT&CK Navigator export     | Provides visual mapping of tactics and techniques                     |
| SIEM integration & forwarding     | Essential for SOC workflows; Dragos excels here                        |
| Threat map or attack timeline     | Helps responders quickly understand incident scope and impact         |
| Plug-in framework                 | Users can extend system with custom playbooks or integrations         |
| TPM/HSM simulation                | Emulates trusted hardware ops for high-assurance environments         |
| Syslog and Kafka output support   | Required for enterprise-grade deployments and integrations            |


## Compliance & Security
- NIST SP 800-53 control mappings (planned)
- FIPS 140-2 crypto simulation
- Comprehensive logging and audit trails
- Chain of custody tracking features

## Disclaimer

This project is intended **solely for authorized security research, simulation, and incident response automation** in **controlled environments** (such as cyber ranges, testbeds, and air-gapped labs). It is **not intended for use in live production ICS/SCADA systems** without thorough testing, validation, and approval by qualified engineering and safety personnel.

The authors and contributors are **not responsible for any damage, disruption, or unintended outcomes** resulting from misuse, incorrect deployment, or modification of this software.

Use responsibly and in accordance with all applicable laws, regulations, and organizational policies.

## Contributing

Pull requests are welcome. Please fork the repo and submit a PR against main.
For roadmap suggestions, open a GitHub issue.

## License
This project is licensed under the MIT License.





<!--
SEO Tags:
ICS incident response, SCADA automation, cyber-physical security, STIX 2.1, MISP integration, Microsoft Teams ICS alerting, OT cyber defense, NIST SP 800-53 ICS, red team PLC detection, ICS SOC tool, real-time ICS response framework, secure SCADA logging
-->


``
