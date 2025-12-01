# SOC Investigation Report: Silent Lynx Payload Deployment

**Report ID** INC-2025-11-19-AZUKI

**Analyst** Danielle Morris

**Date** November 29, 2025

**Incident Date** November 19, 2025

---

## 1. Findings 

### Key Indicators of Compromise (IOCs):

* **Attack Source IP:** 
   * Initial Access IP: `88.97.178.12`
    * Persistent Access IPs: `159.26.106.98`, `149.50.209.165`
* **Compromised Accounts**
  * Initial Compromise/Multi-Target: `kenji.sato`
  * Pivot Host Execution: `yuki.tanaka`
  * Final Deployment Credentials: `fileadmin`
* **Malicious Files and Tools**
  * Initial Scripts: `wupdate.ps1`, `wupdate.bat`
  * Credential Theft Tool: `mm.exe` (Mimikatz)
  * Beacon/Backdoor: `svchost.exe`
  * Final Payload: `silentlynx.exe`
  * Living Off The Land (LOTL) Tools: `7z.exe` (staging), `PsExec64.exe` (deployment), `curl.exe` (exfiltration), `certutil.exe` (download)
* **Persistence Mechanisms**
  * Scheduled Task: `Windows Update Check`
  * Backdoor Account: `support`
* **C2 and Exfiltration**
  * C2 Server (Payload Hosting): `78.141.196.6:8080`
  * Exfiltration Channel: `Discord`
* **Affected Systems/Targets**
  * Initial Access Host: `azuki-sl`
  * Pivot Host (Staging/Deployment): `azuki-adminpc`
  * Critical Target IP: `10.1.0.188`
  * Lateral Movement Targets: `10.1.0.108`, `10.1.0.102`, `10.1.0.204`

### KQL Queries Used:

#### Initial Access & Reconnaissance

#### **Query 1 - Initial Access: ((Brute Force/Password Spray)**

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where Timestamp between (datetime(2025-11-19).. datetime(2025-11-20))
| where not(isempty (RemoteIP))
| where ActionType == "LogonFailed"
| summarize FailedLogons = count() by RemotelP
| order by FailedLogons desc
```

**Results:** High volume of failed RDP logon attempts identified from multiple external IPs, including **115.247.157.74** (43 attempts),  **185.156.73.173** (29 attempts), **92.363.197.9** (28 attempts) and **185.156.73.169** (21 attempts) indicating a widespread brute-force or password spray attack.

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
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where ActionType == "LogonSuccess"
| where not(isempty (RemoteIP))
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, RemoteIP, AccountName, LogonType, Protocol, ActionType
| sort by Timestamp asc
```

**Results:** Confirmed successful RDP logons (**LogonType 10**) on **Nov 19**, **Nov 21**, and **Nov 24** using the compromised account **kenji.sato** from three separate external IP addresses: **88.97.178.12** (Initial Access), **159.26.106.98** (Persistent Access), and **149.50.209.165** (Persistent Access). This confirms the use of rotating infrastructure to maintain access and evade IP-based blocks.

**Attachments:**

*Successful Logon Event*

<img width="1541" height="449" alt="image" src="https://github.com/user-attachments/assets/295a1f65-107f-4b65-9174-9c9c62240857" />

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
**Results:** Execution of **whoami.exe** at 2:03:32 PM and **HOSTNAME.EXE** at 2:03:35 PM confirmed, gathering information about the current user's privileges and the device name.

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
**Results:** Execution of commands **ipconfig.exe /all** at 2:03:56 PM and **ARP.EXE -a** at 2:04:01 PM confirmed for network mapping.

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

**Results:** Registry keys were modified to exclude the temporary staging directories (**C:\Users\KENJI~1.SAT\AppData\Local\Temp** and **C:\ProgramData\WindowsCache**) from Windows Defender scanning.

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

**Results:** Confirmed use of **PowerShell** (`-ExecutionPolicy Bypass` and `Invoke-WebRequest`) to download **`wupdate.ps1`** and **`wupdate.bat`** from C2 **`78.141.196.6:8080`**. Subsequent abuse of **`certutil.exe`** (`-urlcache -f` flags) confirmed the download of the beacon (`svchost.exe`) and credential dumper (`mm.exe`) around **2:07:21 PM**.

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

**Results:** The scheduled task **Windows Update Check** was created at **19:07:00Z** to execute the malicious beacon **C:\ProgramData\WindowsCache\svchost.exe** daily for persistence.

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

**Results:** Execution of **mm.exe** (Mimikatz) confirmed at **19:08:00Z**, attempting to read memory from `lsass.exe`, specifically using the **sekurlsa::logonpasswords** module, indicating credential theft.

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

**Results:** Creation of the compressed archive **export-data.zip** (Flag 14) in the staging directory at **2:08:58 PM** (used for data collection).

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
**Results:** Confirmed the use of **curl.exe** to upload the archive to the cloud service **Discord** on port **443** at **2:09:21 PM**.

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
**Results:** Confirmed the creation of the backdoor administrator account **support** using the `net user support /add` command at **2:09:48 PM**.

**Attachments:**

*Threat Actor Persistence – Support Account Added*

<img width="1117" height="250" alt="image" src="https://github.com/user-attachments/assets/d1985c99-302e-48de-a85d-f7a1077e435d" />

---

#### Lateral Movement & Anti-Forensics

#### Query 13 - RDP Lateral Movement Attempt:

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where Timestamp > datetime(2025-11-19 2:11:40 PM)
| where FileName =~ "mstsc.exe"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by Timestamp asc
```

**Results:** Confirmed multiple programmatic RDP client (**mstsc.exe**) launches, initiated by **powershell.exe**, on **Nov 19**, **Nov 21**, and **Nov 24**. These attempts targeted at least two internal hosts: **10.1.0.188** and **10.1.0.108**, indicating persistent internal network reconnaissance using stolen credentials.

**Attachments:**

*Repeated RDP Activity Toward Internal Hosts*

<img width="1153" height="412" alt="image" src="https://github.com/user-attachments/assets/93895aab-710f-415b-b935-5953fea85ea8" />

---

#### Query 14 - Anti-Forensics / Log Tampering:

```kql
DeviceEvents
| where DeviceName == "azuki-sl"
| where ActionType contains "LogCleared" or ActionType contains "EventLog"
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName
| sort by Timestamp asc
```

**Results:** Confirmed multiple instances of log clearing on the device. The **Security** event log was cleared by **kenji.sato** three times: on **Nov 19 at 2:11:39 PM**, and again on **Nov 25 at 1:07:10 AM** and **1:12:50 AM**. This indicates continuous efforts by the threat actor to destroy forensic evidence following subsequent access and activities.

**Attachments:**

*Unauthorized Log Clearing – Security Log Erasure Events*

<img width="1136" height="203" alt="image" src="https://github.com/user-attachments/assets/b1a28fc8-fa16-4271-8ba8-d307ad86ca12" />

---

#### Query 15 - Payload Extraction on Pivot Host

```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName =~ "7z.exe"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName, DeviceName
| sort by Timestamp asc
```

**Results:** Confirmed payload staging on the pivot host (**azuki-adminpc**) by the **yuki.tanaka** account. The attacker used the archive utility **7z.exe** to extract two suspicious files: **KB5044273-x64.7z** (likely a decoy name) at 11:21:32 PM on **Nov 24** and **m-temp.7z** (likely containing the final **silentlynx.exe** payload) at 12:55:44 AM on **Nov 25**.

**Attachments:**

*Observed Payload Preparation via 7z.exe*

<img width="1798" height="170" alt="image" src="https://github.com/user-attachments/assets/3670cdca-0870-42d9-9c94-269830e76804" />

---

#### Query 16 - Payload Deployment via PsExec:

```kql

DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where Timestamp between (datetime(2025-11-25 00:00).. datetime(2025-11-26 00:00))
| where FileName has_any ("PsExec.exe", "PsExec64.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessAccountName, DeviceName
| sort by Timestamp asc

```

**Results:** Confirmed successful **PsExec** deployment of the **silentlynx.exe** payload, initiated by the **yuki.tanaka** account, across multiple internal hosts:

* Targeting **10.1.0.102** using compromised account **kenji.sato** at 1:03:47 AM.
* Targeting **10.1.0.188** using compromised account **fileadmin** (likely the critical target) at 1:04:40 AM.
* Targeting **10.1.0.204** using compromised account **kenji.sato** at 1:05:46 AM.

This confirms a successful multi-target deployment of the final payload.

*PsExec Lateral Movement – silentlynx.exe Deployment Across Hosts*

<img width="1794" height="253" alt="image" src="https://github.com/user-attachments/assets/da0b580d-c761-4428-9cb1-efc21b4554a9" />

---
## 2. Investigation Summary 

### What Happened:

The organization Azuki Import/Export Trading Co. was compromised by the financially motivated threat actor **JADE SPIDER** (`Silent Lynx`) via a successful **RDP** login on `Nov 19, 2025`, using the `kenji.sato` account. The initial attack established **persistence** (via scheduled task and a backdoor `support` account), stole high-value credentials (including `fileadmin`), and exfiltrated data to `Discord`. Over the next six days, the attacker maintained persistent access from a **rotating set of external IPs**, repeatedly clearing **security logs** to evade detection. The threat actor then used the **AZUKI-AdminPC** pivot host, leveraging the `yuki.tanaka` account, to stage and deploy the final malware payload, `silentlynx.exe`, onto multiple internal systems—including the critical target `10.1.0.188`—using the **PsExec** utility.

<img width="116" height="112" alt="image" src="https://github.com/user-attachments/assets/0c5f82a8-8d15-4d64-94ff-3c8125c086c1" />

---
### Attack Timeline:

| Field | Detail |
| :--- | :--- |
| **Started** (First Successful Login) | 2025-11-19T18:36:18Z |
| **Ended** (Last Observed Activity)| 2025-11-25T06:04:40Z  |
| **Duration** | 5 days, 11 hours, 28 minutes, 22 seconds |
| **Impact Level** | **Critical** (Successful lateral movement and payload deployment) |

---

## 3. Who, What, When, Where, Why, How

### Who

| Field | Detail |
| :--- | :--- |
| **Attacker Origin** | Multiple external IPs: `88.97.178.12` (Initial Access), `159.26.106.98`, `149.50.209.165` (Confirming rotating infrastructure) |
| **Threat Group** | **JADE SPIDER** (Aliases: APT-SL44, **SilentLynx**) |
| **Attribution Confidence** | High |
| **Compromised Accounts** | `kenji.sato` (Initial Access), `yuki.tanaka` (Pivot Execution), `fileadmin` (Stolen Credential), and the backdoor `support` account (Created by attacker). |
| **Affected Systems** | `azuki-sl` (Initial Host), `azuki-adminpc` (Pivot/Staging Host), `10.1.0.188` (Critical Target), `10.1.0.102`, `10.1.0.204` (Additional PsExec Targets). |
| **Impact on Users** | Unauthorized access, credential theft, and successful network propagation. |

---

### What

| Field | Detail |
| :--- | :--- |
| **Attack Type** | RDP Brute-Force leading to a Multi-Stage Intrusion, Credential Theft, and Lateral Movement. |
| **Malicious Activities** | Initial Access (RDP Compromise), Reconnaissance, Defense Evasion (Defender exclusion & hidden files), Credential Dumping (**`mm.exe`**), Data Staging (`export-data.zip`), Data Exfiltration (Discord), Lateral Movement (**`PsExec64.exe`**), and Remote Code Execution (Deployment of **`silentlynx.exe`**). |
| **Payloads Deployed** | Initial access scripts (`wupdate.ps1`, `wupdate.bat`), Credential Dumper (`mm.exe`), Final Beacon/Malware (`silentlynx.exe`). |
| **Data Targeted** | Stolen credentials (including `fileadmin`), and general data compressed into `export-data.zip`. |
---

### When 

| Event | Detail |
| :--- | :--- |
| **Attack Start** | 2025-11-19T18:45:15Z  (First Failed RDP) |
| **First Malicious Activity** | **2025-11-19T18:36:18Z** (First command executed after successful login) |
| **Silent Lynx Deployed** | 2025-11-25T04:21:33Z (File Created on Pivot Host) |
| **Last Observed Activity** | **2025-11-25T06:04:40Z** (UTC) |
| **Total Attack Duration** | **5 days, 11 hours, 28 minutes, 22 seconds** |
| **Detection Time** | 3 Days (Detected on 2025-11-22, new activity on 2025-11-25) |
| **Is it still active?** | **Yes** (Persistence mechanisms remain, and lateral movement was successful). |

---

### Where

| Field | Detail |
| :--- | :--- |
| **Attack Origin (External)** | The attack originated from a pool of rotating external IPs: `88.97.178.12`, `159.26.106.98`, and `149.50.209.165`. |
| **C2 and Exfil Location** | **Command & Control (C2):** The threat actor's payload server was located at `78.141.196.6:8080`. **Exfiltration:** Data was sent to the cloud service `Discord` via port `443`. |
| **Initial Target System** | `azuki-sl` (The host where initial RDP access, persistence, and data collection occurred). |
| **Pivot System** | `azuki-adminpc` (The host used to stage the final payload and launch PsExec for lateral movement). |
| **Final Targets (Internal)** | `10.1.0.188` (Critical Host) and the surrounding internal network systems `10.1.0.102`, `10.1.0.204`, and `10.1.0.108` (recon target). |
| **Network Segment** | The initial target (`azuki-sl`) and all internal movement targets (e.g., `10.1.0.X`) are within the internal network/private addressing space. |
| **Affected Directories/Files** | `C:\ProgramData\WindowsCache` (Malware staging, hidden directory), `C:\Users\KENJI~1.SAT\AppData\Local\Temp\` (Temporary script download), and `C:\Windows\Temp\cache\` (Final payload staging on `azuki-adminpc`). |

---

### Why (Motive)

| Field | Detail |
| :--- | :--- |
| **Likely Motive** | **Financially motivated** via a multi-stage approach, including **data extortion** (competitor intelligence theft) and **ransomware pre-positioning** (Silent Lynx deployment). |
| **Target Value** | Specific high-value data (**Pricing and supplier data**) and access to critical internal infrastructure, evidenced by lateral movement to **`10.1.0.188`**. |

---

### How (Attack Techniques)

| Field | Detail |
| :--- | :--- |
| **Initial Access Method** | RDP Brute Force (Query 1) to gain entry using the compromised `kenji.sato` account from the initial IP `88.97.178.12`. |
| **Tools/Techniques Used** | **Execution/Download (LOTL):** `powershell` (`Invoke-WebRequest`), `certutil.exe`. **Defense Evasion:** `attrib.exe` (`+h +s`), Registry modification. **Credential Theft:** `mm.exe`. **Staging/Deployment:** `7z.exe`, `PsExec64.exe`. **Exfiltration:** `curl.exe`. |
| **Persistence Method** | Scheduled Task (`Windows Update Check` to run `svchost.exe`) and creation of a Backdoor Administrator Account (`support`). Attacker also relied on repeated RDP Logons using rotating IPs (Query 2). |
| **Defense Evasion** | Registry modification to set Windows Defender Exclusions on staging directories and three separate instances of clearing the **Security Event Log** (`LogCleared`) on the initial host. |
| **Lateral Movement** | Used stolen credentials (`kenji.sato`, `fileadmin`) to launch RDP client (`mstsc.exe`) and later executed `PsExec64.exe` from the pivot host `azuki-adminpc` to push the final payload to three different targets. |
| **Data Collection Method** | Used `mm.exe` (Mimikatz) for **Credential Dumping** from `lsass.exe` memory, followed by file compression into `export-data.zip`. |
| **Communication Method** | HTTP/S for malware download from `78.141.196.6:8080` and HTTPS for exfiltration using `curl.exe` to the cloud service **Discord**. |

---

## 4. Full Attack Timeline & Tactics


---

## 5. Recommendations

### Immediate Actions Needed:

1.  **Isolate Affected Systems:** Immediately quarantine **AZUKI-SL**, **AZUKI-AdminPC**, and **`10.1.0.188`** from the network to halt C2 activity and propagation.
2.  **Reset Compromised Credentials:** **URGENT:** Force a password reset for **`kenji.sato`**, **`yuki.tanaka`**, and the critical **`fileadmin`** account. Disable/remove the backdoor account **`support`**.
3.  **Remediate Payloads:** Remove the **`PSEXESVC.exe`** service and the deployed **`silentlynx.exe`** payload from **`10.1.0.188`**.
4.  **Block IOCs:** Implement blocks at the firewall/perimeter for C2 **`78.141.196.6`**, the initial access IP **`88.97.178.12`**, and all outbound traffic to **Discord**.
5.  **Expand Investigation / Endpoint Audit:** Begin an immediate threat hunt across the entire network to confirm no other devices or accounts were compromised by the stolen credentials or lateral movement attempts.

### Short-term Improvements (1-30 days):

1.  **System Restoration:** Restore all three compromised hosts from known clean backups dating **before Nov 19, 2025, 1:36 PM**.
2.  **Account Privilege Audit:** Audit and limit the administrative privileges of accounts like **`fileadmin`** to prevent them from being abused for lateral movement with generic tools.
3.  **Application Control (Interim):** Implement an interim rule to prevent execution of unapproved binaries (`PsExec64.exe`, `mm.exe`, `7z.exe`) from user-writable and temporary directories.

### Long-term Security Enhancements:

1.  **MFA Implementation:** Mandate **Multi-Factor Authentication (MFA)** for all RDP, VPN, and administrative logons to eliminate initial access via compromised credentials.
2.  **Endpoint Hardening:** Implement full **Application Control** policies (e.g., Windows Defender Application Control) across all endpoints to block unauthorized execution of attack tools.
3.  **Network Segmentation:** Improve **network segmentation** between endpoints and critical systems to limit the effectiveness of lateral movement (LM) should a host be compromised.
