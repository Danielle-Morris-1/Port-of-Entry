<img width="451" height="672" alt="image" src="https://github.com/user-attachments/assets/88dc4fe4-1901-454f-9554-e0d6c058d8ec" />

# SOC Investigation Report Part One: Port of Entry

**Report ID** INC-2025-11-19-AZUKI

**Analyst** Danielle Morris

**Date** November 29, 2025

**Incident Date** November 19, 2025

---

## 1. Findings 

### Key Indicators of Compromise (IOCs):

* **Attack Source IP:**
    * Initial Access IP: `88.97.178.12`
* **Compromised Accounts**
    * Initial Compromise: `kenji.sato`
    * Stolen Credentials: `fileadmin`
* **Malicious Files and Tools**
    * Initial Scripts: `wupdate.ps1`, `wupdate.bat`
    * Credential Theft Tool: `mm.exe` (Mimikatz)
    * Beacon/Backdoor: `svchost.exe`
    * LOTL Tools Used: `curl.exe` (exfiltration), `certutil.exe` (download)
* **Persistence Mechanisms**
    * Scheduled Task: `Windows Update Check`
    * Backdoor Account: `support`
* **C2 and Exfiltration**
    * C2 Server (Payload Hosting): `78.141.196.6:8080`
    * Exfiltration Channel: `Discord`
* **Affected Systems/Targets**
    * Initial Access Host: `azuki-sl`
    * Probed Target IP: `10.1.0.188` (Targeted via `mstsc.exe`)

### KQL Queries Used:

#### Initial Access & Reconnaissance

#### **Query 1 - Initial Access: (Brute Force/Password Spray)**

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19).. datetime(2025-11-20))
| where not(isempty (RemoteIP))
| where ActionType == "LogonFailed"
| summarize FailedLogons = count() by RemotelP
| order by FailedLogons desc
```

**Results:** High volume of failed RDP logon attempts identified from multiple external IPs, including `115.247.157.74` (**43** attempts),  `185.156.73.173` (**29** attempts), `92.363.197.9` (**28** attempts) and `185.156.73.169` (**21** attempts) indicating a widespread brute-force or password spray attack.

**Attachments:**

*Initial Access*

<img width="622" height="441" alt="image" src="https://github.com/user-attachments/assets/9d84427a-a55a-408b-b9fb-bf38ea4bee07" />

---

*Malicious IP Analysis – AbuseIPDB*

<img width="661" height="510" alt="image" src="https://github.com/user-attachments/assets/7eb6eebd-80f5-43db-91e9-73a24b4bf114" />


---

<img width="628" height="389" alt="image" src="https://github.com/user-attachments/assets/9cecb399-55df-47b9-8055-2aa7bc0d9eb6" />


---

#### Query 2 - Successful Initial Access:

```kql
//Custom time range: Wed Nov 19 2025 11:47:16 AM - Thu Nov 20 2025 11:47:16 AM
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where ActionType == "LogonSuccess"
| where not(isempty (RemoteIP))
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, RemoteIP, AccountName, LogonType, Protocol, ActionType
| sort by Timestamp asc
```

**Results:** Confirmed successful RDP logon on **Nov 19** using the compromised account `kenji.sato` from the external IP addresses `88.97.178.12` at **1:36:21 PM**.

**Attachments:**

*Successful Logon Event*

<img width="1520" height="169" alt="image" src="https://github.com/user-attachments/assets/7011b67f-d37b-4ee4-bc91-8bd5aa73caeb" />


---

*Geolocation Evidence*

<img width="852" height="544" alt="image" src="https://github.com/user-attachments/assets/2bc69d97-d5e7-4f13-8666-cf476f5913be" />



---

#### Query 3 - Identity Enumeration:

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where ProcessCommandLine has_any (
      "whoami",
      "hostname",
      "query user",
      "net user",
      "net group",
      "net localgroup"
)
| project Timestamp, FileName, ProcessCommandLine, AccountName
| sort by Timestamp asc
```
**Results:** Execution of `whoami.exe` at **2:03:32 PM** and `HOSTNAME.EXE` at **2:03:35 PM** confirmed, gathering information about the current user's privileges and the device name.

**Attachments:**

*Observed Enumeration Commands*

<img width="1010" height="157" alt="image" src="https://github.com/user-attachments/assets/2cb8660b-7bed-43b5-83c4-c53888b6fcd5" />

---

#### Query 4 - Network Reconnaissance:

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19).. datetime(2025-11-20))
| where InitiatingProcessAccountName == "kenji.sato"
| where ProcessCommandLine has_any ("-a", "net view", "ipconfig")
| project Timestamp, ProcessCommandLine, AccountName, FileName
| order by Timestamp asc
```
**Results:** Execution of commands `ipconfig.exe /all` at **2:03:56 PM** and `ARP.EXE -a` at **2:04:01 PM** confirmed for network mapping.

**Attachments:**

*Observed Reconnaissance Commands*

<img width="1021" height="177" alt="image" src="https://github.com/user-attachments/assets/daa2383c-639e-4da0-9133-bd575f7d8215" />

---

#### Execution, Evasion, and Persistence

#### Query 5 - Malware Staging Setup (Hiding Directory):

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where ProcessCommandLine has "attrib" and ProcessCommandLine has "+h"
| project Timestamp, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, DeviceName


```

**Results:** The command `attrib.exe +h +s C:\ProgramData\WindowsCache` was executed at **2:05:33 PM** to create and hide the primary malware staging directory.

**Attachments:**

*Hidden Malware Directory Creation – attrib.exe Execution*

<img width="1863" height="128" alt="image" src="https://github.com/user-attachments/assets/44b0f437-4c8a-4f0a-99df-0393e0ba9fe0" />


---
#### Query 6 - Windows Defender Exclusion:

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where RegistryKey contains "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project Timestamp, RegistryKey, RegistryValueName, InitiatingProcessCommandLine, RegistryValueData
| sort by Timestamp asc
| limit 5

```

**Results:** Registry keys were modified to exclude the temporary staging directories (`C:\Users\KENJI~1.SAT\AppData\Local\Temp` and `C:\ProgramData\WindowsCache`) from Windows Defender scanning.

**Attachments:**

*Observed Defender Exclusion Changes*

<img width="798" height="474" alt="image" src="https://github.com/user-attachments/assets/0f1a310b-4a17-49bb-b22e-ac4b7e33a066" />

---

#### Query 7 - Download Utility Abuse (LOTL) & Initial Script Download:

```kql

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where FileName has_any ("certutil.exe", "bitsadmin.exe", "powershell.exe")
| where ProcessCommandLine has_any ("http", "https", "-urlcache", "Invoke-WebRequest")
| project Timestamp, FileName, ProcessCommandLine
| sort by Timestamp asc

```

**Results:** Confirmed use of **PowerShell** (`-ExecutionPolicy Bypass` and `Invoke-WebRequest`) to download `wupdate.ps1` and `wupdate.bat` from C2 **`78.141.196.6:8080`**. Subsequent abuse of `certutil.exe` (`-urlcache -f` flags) confirmed the download of the beacon (`svchost.exe`) and credential dumper (`mm.exe`) around **2:07:21 PM**.

**Attachments:**

*C2 Download Observed – wupdate.ps1 / wupdate.bat*

<img width="1784" height="729" alt="image" src="https://github.com/user-attachments/assets/8b385349-461b-4067-bd8d-3bbe42a7b3c8" />



---
#### Query 8 - Scheduled Task Persistence:

```kql

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_all ("/create", "/tn")
| project Timestamp, FileName, ProcessCommandLine
| sort by Timestamp asc
```

**Results:** The scheduled task **Windows Update Check** was created at **2:07:46 PM** to execute the malicious beacon `C:\ProgramData\WindowsCache\svchost.exe` daily for persistence.

**Attachments:**

*Malicious Scheduled Task Creation – svchost.exe Execution*

<img width="1535" height="150" alt="image" src="https://github.com/user-attachments/assets/81205533-093f-4eda-915b-d909f43f9cc2" />


---

#### Query 9 - Credential Dumping Execution:


```kql
DeviceEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where FileName contains "lsass.exe"
| where ActionType == "ReadProcessMemoryApiCall"
| project Timestamp, InitiatingProcessFileName, FileName, ActionType, InitiatingProcessVersionInfoOriginalFileName
| sort by Timestamp asc

```

**Results:** Execution of `mm.exe` (Mimikatz) confirmed at **2:09:31 PM**, attempting to read memory from `lsass.exe`, specifically using the `sekurlsa::logonpasswords` module, indicating credential theft.

**Attachments:**

*Observed Memory Access – Mimikatz Evidence Capture*

<img width="595" height="249" alt="image" src="https://github.com/user-attachments/assets/cd29b8d3-e149-46be-babf-44ec14d6eab1" />

---

#### Collection & Exfiltration

#### Query 10 - Data Staging and Compression:

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where ActionType == "FileCreated"
| where FolderPath has "WindowsCache"
| where FileName endswith ".zip"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp asc

```

**Results:** Creation of the compressed archive `export-data.zip` in the staging directory at **2:08:58 PM** (used for data collection).

**Attachments:**

*Suspicious Data Collection – Archive Creation*

<img width="1266" height="270" alt="image" src="https://github.com/user-attachments/assets/3fe18b75-b746-4ce0-9480-e47300041d44" />

---

#### Query 11 - Exfiltration Channel:


```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessFileName contains "curl.exe"
| project Timestamp, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| sort by Timestamp asc

```
**Results:** Confirmed the use of `curl.exe` to upload the archive to the cloud service **Discord** on port **443** at **2:09:21 PM**.

**Attachments:**

*Observed Exfiltration Method – curl.exe to Discord*

<img width="1245" height="212" alt="image" src="https://github.com/user-attachments/assets/c82a82f8-e7e8-439a-aa9a-3312a2303792" />

---

#### Query 12 - Backdoor Account Persistence:

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName in ("net.exe", "net1.exe")
| where ProcessCommandLine has "/add"
| where ProcessCommandLine has_any ("user", "administrators")
| project Timestamp, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```
**Results:** Confirmed the creation of the backdoor administrator account `support` using the `net user support /add` command at **2:09:48 PM**.

**Attachments:**

*Threat Actor Persistence – Support Account Added*

<img width="1117" height="250" alt="image" src="https://github.com/user-attachments/assets/d1985c99-302e-48de-a85d-f7a1077e435d" />

---

#### Lateral Movement & Anti-Forensics

#### Query 13 - RDP Lateral Movement Attempt:

```kql
//Custom time range: Wed Nov 19 2025 11:47:16 AM - Thu Nov 20 2025 11:47:16 AM
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName =~ "mstsc.exe"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

**Results:** Confirmed RDP client (`mstsc.exe`) launch, initiated by **powershell.exe**,  Tthat targeted the internal host: **10.1.0.188**, indicating internal network reconnaissance using stolen credentials.

**Attachments:**

*RDP Activity Toward Internal Host*

<img width="1080" height="156" alt="image" src="https://github.com/user-attachments/assets/f711fba9-0599-49cc-90c5-9a64a8e90f19" />

---

#### Query 14 - Anti-Forensics / Log Tampering:

```kql
//Custom time range: Wed Nov 19 2025 11:47:16 AM - Thu Nov 20 2025 11:47:16 AM
DeviceEvents
| where DeviceName == "azuki-sl"
| where ActionType contains "LogCleared" or ActionType contains "EventLog"
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName
| sort by Timestamp asc
```

**Results:** The **Security** event log was cleared by `kenji.sato` at **2:11:39 PM**.

**Attachments:**

*Unauthorized Log Clearing – Security Log Erasure Event*

<img width="585" height="192" alt="image" src="https://github.com/user-attachments/assets/79729ada-b8e9-4c0e-a294-c8653d05abeb" />

---
## 2. Investigation Summary 

### What Happened: Initial Compromise

The organization Azuki Import/Export Trading Co. was compromised by the financially motivated threat actor **JADE SPIDER** (Silent Lynx) via a successful **RDP** login on **November 19, 2025**, using the **`kenji.sato`** account. The attack was a rapid, hands-on-keyboard operation focused entirely on the initial host, **`azuki-sl`**. Within a 35-minute window, the attacker established immediate **persistence** (via scheduled task and a backdoor `support` account), stole high-value credentials (including **`fileadmin`** via Mimikatz), and successfully exfiltrated collected data to **Discord** before attempting to clear their tracks with an anti-forensics log clear.

---

### Attack Timeline:

| Field | Detail |
| :--- | :--- |
| **Started** (First Successful Login) | 2025-11-19T18:36:18Z |
| **Ended** (Last Observed Activity)| 2025-11-19T19:11:39Z  |
| **Duration** | Approximately 35 minutes |
| **Impact Level** | **Critical** (Successful lateral movement) |

---

## 3. Who, What, When, Where, Why, How

### Who

| Field | Detail |
| :--- | :--- |
| **Attacker Origin** | External IPs: `88.97.178.12` |
| **Attribution Confidence** | High |
| **Compromised Accounts** | `kenji.sato` (Initial Access), `fileadmin` (Stolen Credential), and the backdoor `support` account (Created by attacker). |
| **Affected Systems** | `azuki-sl` |
| **Impact on Users** | Account compromise, credential theft, and successful data exfiltration. |

---

### What

| Field | Detail |
| :--- | :--- |
| **Attack Type** | RDP Brute-Force leading to an hands-on-keyboard operation focused on Persistence, Credential Theft, and Data Exfiltration. |
| **Malicious Activities** | **Reconnaissance** (`ipconfig`, `arp`), **Defense Evasion** (Windows Defender exclusion, one log clear), **Credential Dumping** (`lsass.exe` memory read), **Data Staging** (`export-data.zip`), and **Data Exfiltration** to Discord. |
| **Payloads Deployed** | Initial access scripts (`wupdate.ps1`, `wupdate.bat`), Credential Dumper (`mm.exe`), Beacon/Backdoor (`svchost.exe`). |
| **Data Targeted** | Stolen credentials (including `fileadmin`), and general data compressed into `export-data.zip`. |

---

### When 

| Event | Detail |
| :--- | :--- |
| **First Failed Logon** | Nov 19, 2025, 2025 8:45:15Z |
| **First Malicious Activity** | Nov 19, 2025, 13:36:18Z (Initial RDP Logon by `kenji.sato`) |
| **Last Observed Activity** | Nov 19, 2025, 19:11:39Z (First log clear on `azuki-sl`) |
| **Activity Span** | Approximately **35 minutes** |
| **Detection Time** | 3 Days (Detected on 2025-11-22) |
| **Is it still active?** | **Yes** (Persistence mechanisms remain). |

---

### Where

| Field | Detail |
| :--- | :--- |
| **Attack Origin (External)** | Single external IP: **`88.97.178.12`**. |
| **C2 and Exfil Location** | **Command & Control (C2):** The payload server was located at **`78.141.196.6:8080`**. **Exfiltration:** Data was sent to the cloud service **`Discord`** via port 443. |
| **Target System (Internal)** | **`azuki-sl`** (The sole host successfully compromised on this day). |
| **Affected Directories/Files** | **`C:\ProgramData\WindowsCache`** (Malware staging, hidden directory) and **`C:\Users\KENJI~1.SAT\AppData\Local\Temp\`** (Temporary script download location). |
| **Network Segment** | The initial target (`azuki-sl`) is within the **internal network/private addressing space**. |
| **Lateral Recon Destination** | The attacker probed internal system **`10.1.0.188`** using RDP (`mstsc.exe`) from `azuki-sl`. |

---

### Why (Motive)

| Field | Detail |
| :--- | :--- |
| **Likely Motive** | Primarily **Financially motivated**, focused on **immediate data theft/espionage** (evidenced by credential dumping and Discord exfiltration) and **establishing a persistent foothold** for future monetization. |
| **Target Value** | Access to high-value data (credentials and files compressed in **`export-data.zip`**) and an attempt to probe access to critical internal infrastructure (evidenced by the RDP probe to **`10.1.0.188`**). |

---

### How (Attack Techniques)

| Field | Detail |
| :--- | :--- |
| **Initial Access Method** | **RDP Brute Force** to gain entry using the compromised **`kenji.sato`** account from the initial IP **`88.97.178.12`**. |
| **Execution Method** | Used **Living Off The Land (LOTL)** binaries: **`powershell.exe`** (`Invoke-WebRequest` with `-ExecutionPolicy Bypass`) and **`certutil.exe`** (`-urlcache -f`) for downloads. |
| **Persistence Method** | **Scheduled Task** (`Windows Update Check` to run `svchost.exe`) and creation of a **Backdoor Administrator Account** (`support`). |
| **Defense Evasion** | Registry modification to set **Windows Defender Exclusions** and a **single instance** of clearing the **Security Event Log** (`LogCleared`). |
| **Lateral Movement** | **Attempted:** Launched RDP client (`mstsc.exe`) targeting internal IP **`10.1.0.188`** from the initial host using stolen credentials. |
| **Data Collection Method** | Used **`mm.exe`** (Mimikatz) for **Credential Dumping** from `lsass.exe` memory, followed by file compression into **`export-data.zip`**. |
| **Communication Method** | **HTTP/S** for malware download from **`78.141.196.6:8080`** and **HTTPS** for exfiltration using **`curl.exe`** to the cloud service **Discord**. |

---

## 4. Recommendations for Findings

### Immediate Actions Needed:

1.  **Isolate Affected System:** Immediately quarantine **`azuki-sl`** from the network to halt any potential beaconing or further C2 activity.
2.  **Reset Compromised Credentials:** Force a password reset for **`kenji.sato`** and the critical stolen credential **`fileadmin`**. Disable/remove the backdoor account **`support`**.
3.  **Remediate Persistence:** Immediately identify and remove the malicious scheduled task **`Windows Update Check`** and the beacon file (`svchost.exe`) from **`azuki-sl`**.
4.  **Block IOCs:** Implement blocks at the firewall/perimeter for C2 **`78.141.196.6`**, the successful access IP **`88.97.178.12`**, and the **top brute-force IPs** (e.g., `115.247.157.74`, `185.156.73.173`). Also block all outbound traffic to the exfiltration channel **`Discord`**.
5.  **Expand Investigation:** Review network logs for the RDP reconnaissance attempts to **`10.1.0.188`** to confirm no successful lateral access occurred using the stolen credentials.

### Short-term Improvements (1-30 days):

1.  **System Restoration:** Restore **`azuki-sl`** from a known clean backup dating **before Nov 19, 2025, 13:35:00Z**.
2.  **Account Privilege Audit:** Audit and immediately restrict the privileges of high-value service accounts like **`fileadmin`** that were exposed.
3.  **Application Control (Interim):** Implement an interim rule to prevent execution of unapproved tools (`mm.exe`, `curl.exe`, `certutil.exe`) from user-writable and temporary directories.

### Long-term Security Enhancements:

1.  **MFA Implementation:** Mandate **Multi-Factor Authentication (MFA)** for all RDP, VPN, and administrative logons to prevent initial access via compromised credentials.
2.  **RDP Hardening:** Implement a robust **account lockout policy** for RDP and restrict RDP access to only trusted source IPs (e.g., VPN gateways).
3.  **Endpoint Logging:** Ensure all security event logs (especially Security, System, and PowerShell logs) are set to maximum retention and are ingested into a central SIEM/log collector, with alerts established for log clearing activity.

---

Report Status: Complete

Next Review: 2025-12-29 (30 days from now)

Distribution: Cyber Range
