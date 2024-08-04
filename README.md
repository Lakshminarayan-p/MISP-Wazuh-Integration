# Wazuh MISP Integration

Integrate Wazuh with IOC (Indicators of Compromise) from MISP - Open Source Threat Intelligence Platform

## Wazuh

Wazuh is an open-source security monitoring platform that provides comprehensive visibility, security monitoring, and incident response capabilities across your infrastructure. It collects and analyzes security data from endpoints, servers, and cloud environments to detect threats and vulnerabilities.

Using advanced analytics and machine learning, Wazuh can automatically detect anomalous and malicious activities, identify and group related events, and generate prioritized alerts to help security teams focus on the most critical threats.

## MISP

The MISP threat sharing platform is a free and open-source software helping information sharing of threat intelligence, including cyber security indicators.

MISP is a threat intelligence platform for gathering, sharing, storing, and correlating Indicators of Compromise of targeted attacks, threat intelligence, financial fraud information, vulnerability information, or even counter-terrorism information.

Many organizations use MISP to maintain an internal repository of IOCs involved in any security incident of the organization.

MISP has rich RESTful API support to integrate with any producers or consumers of threat intelligence information.

## Requirements

- Linux
- Python 3
- apscheduler

## Installation

Clone the repository:

```bash
git clone https://github.com/your-repo/Wazuh-MISP-Integration.git
```

### Configuration:

Edit the integration.py file with favourite editor and provide the following information.

```sh
misp_auth_key = "mxVt2yZWkS39XemrgtyhbfYts7ZeeheQ50dXKLHO"
wazuh_auth_key = "YOUR_WAZUH_AUTH_KEY"
wazuh_group = "YOUR_WAZUH_GROUP"
misp_server = "IP Address of MISP Server"
wazuh_server = "IP Address of Wazuh Server"
frequency = 60 # In minutes
```

### Usage:
```sh
python3 integration.py >> /var/log/misp-wazuh-integration.log &
```

### Error Handling - Use Cases
 - Validate if the Wazuh group exists
 - Fetch and parse IOCs from MISP
 - Socket connection validation for Wazuh and MISP


### Output - Success

```
17:05:50 -- Checking HTTPS Connectivity to Wazuh
17:05:50 -- (Success) HTTPS Connectivity to Wazuh
17:05:50 -- Checking HTTPS Connectivity to MISP
17:05:50 -- (Success) HTTPS Connectivity to MISP
17:05:50 -- Initiating, GET data from MISP on <IP Address of MISP Server>
17:05:51 -- MISP API Query (Success)
17:05:51 -- 36 IOCs imported
17:05:51 -- Initiating, IOC POST to Wazuh
17:05:51 -- Imported 36 IOCs to Wazuh (Success)
```
