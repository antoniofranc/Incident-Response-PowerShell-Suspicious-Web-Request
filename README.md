<img width="450" height="450" alt="image" src="https://github.com/user-attachments/assets/ba648d21-0888-43ea-9aea-8c2ba54cdadd" />

# Incident Response PowerShell Suspicious Web Request

## Project Overview
This project demonstrates the implementation of a security detection rule in Microsoft Sentinel to identify and respond to suspicious PowerShell activity. Specifically, it focuses on detecting when PowerShell's `Invoke-WebRequest` command is used to download potentially malicious payloads from the internet a common post-exploitation technique used by threat actors.

## Technologies Used
- Microsoft Sentinel - Cloud-native SIEM for security analytics and threat intelligence
- Microsoft Defender for Endpoint (MDE) - Endpoint detection and response platform
- Log Analytics Workspace - Centralized log collection and querying
- Kusto Query Language (KQL) - Query language for log analysis
- PowerShell - Command-line shell used for attack simulation
- NIST 800-61 - Incident Response Lifecycle framework

## Scenario
A user reports unusual behavior after clicking a link in an email. Unknown to them, the link executed a script that:
1. Launched a hidden PowerShell command on the system.

2. Used Invoke-WebRequest / Invoke-RestMethod to reach out to an external server.

3. Downloaded a secondary script, containing the attacker’s actual payload.

4. Immediately executed the downloaded script.

5. Attempted to:
- Enroll the host into a botnet
- Establish stealthy remote control
- Exfiltrate sensitive data
All malicious activity originated from a single user action, followed by an automated chain of PowerShell-based events.

By using built-in utilities and commands like `Invoke-WebRequest`, attackers can blend in with normal system activity and bypass traditional defenses. Detecting this behavior is critical to identifying and disrupting ongoing attacks.
<img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/b1d97c2d-dc0f-49fd-ba9d-c13e33628bd8" />

----
## Part 1: Create Alert Rule (PowerShell Suspicious Web Request)
Design a Sentinel Scheduled Query Rule that detects when PowerShell uses `Invoke-WebRequest` to download content from the internet.
## KQL Query
```
let TargetHostname = "windows-target-1";
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine has "Invoke-WebRequest"
| order by TimeGenerated
```
<img width="1740" height="113" alt="image" src="https://github.com/user-attachments/assets/e521e308-81f7-4ff2-a4b6-caef28b90781" />



## Analytics Rule Configuration
Navigate in Microsoft Sentinel:  
**Sentinel → Analytics → Create → Scheduled Query Rule**

| **Setting**           | **Value**                                                                 |
|-----------------------|---------------------------------------------------------------------------|
| **Name**              | PowerShell Suspicious Web Request                                         |
| **Description**       | Detects PowerShell processes using `Invoke-WebRequest` to download content from the internet, which may indicate malicious payload downloads |
| **Status**            | Enabled                                                                   |
| **MITRE ATT&CK**      |  T1071.001 (Application Layer Protocol: Web Protocol) <br> T1059.001 (Command Scripting Interpreter: PowerShell) <br> T1105 (Command and Control: Ingress Tool Transfer) <br> T1203 (Execution: Explotaton for Client Execution)  <br> T1041 (Exfiltration Over C2 Channel)|
| **Query Frequency**   | Every 4 hours                                                             |
| **Lookup Period**     | Last 24 hours                                                             |
| **Alert Threshold**   | Greater than 0 results                                                    |
| **Query Suppression** | Stop running after alert generated (24 hours)                             |

<img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/e0a592ef-20a3-4a1c-bef9-8b27a68a23d7" />


## Entity Mappings

| **Entity Type** | **Identifier**  | **Value**              |
|------------------|------------------|--------------------------|
| Account          | Name             | AccountName              |
| Host             | HostName         | DeviceName               |
| Process          | CommandLine      | ProcessCommandLine       |


## Part 2: Work Incident
Following the NIST 800-61 Incident Response Lifecycle, we'll investigate and respond to this incident.

Diagram of NIST 800-61 phases: Preparation, Detection & Analysis, Containment/Eradication/Recovery, Post-Incident Activities
<img width="300" height="326" alt="image" src="https://github.com/user-attachments/assets/0cc47bb6-88b3-47b4-a5fd-6635e7257040" />

