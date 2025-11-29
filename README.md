# SOC Investigation Report: Port of Entry

**Report ID** INC-2025-11-19-AZUKI

**Analyst** Danielle Morris

**Date** November 29, 2025

**Incident Date** November 19, 2025

---

## 1. Findings (Required)

### Key Indicators of Compromise (IOCs):

* **Attack Source IP:** `88.97.178.12`
* **Compromised Account:** `kenji.sato`
* **Malicious Script:** `wupdate.ps1`
* **Credential Theft Tool:** `mm.exe`
* **Persistence Mechanism:** Scheduled Task: `Windows Update Check`
* **C2 Server:** `78.141.196.6`
* **Exfiltration Channel:** `Discord`
* **Secondary Target IP:** `10.1.0.188`

---

## 2. Investigation Summary 

### What Happened:
The organization Azuki Import/Export Trading Co. was compromised by the financially motivated threat actor JADE SPIDER via RDP. The attacker established persistence, stole the credentials for a second system, collected and compressed critical pricing data, and exfiltrated the archive before clearing the security logs.

---

### Key Incident Details

| Field | Detail |
| :--- | :--- |
| **Threat Group** | JADE SPIDER (Aliases: APT-SL44, SilentLynx) |
| **Victim Account** | `kenji.sato` |
| **Affected System** | AZUKI-SL (IT admin workstation) |
| **Impact on Users** | Unauthorized data theft, potential further network compromise. |

---

### When (Attack Timeline)

| Event | Detail |
| :--- | :--- |
| **First Malicious Activity** | Nov 19, 2025, approx. 1:36 PM UTC |
| **Last Observed Activity** | Nov 19, 2025, 2:11:39 PM UTC (Log Clearing) |
| **Total Attack Duration** | ~35 minutes |
| **Is it still active?** | **Yes** (Persistence mechanisms remain, including the support account). |

---

### Where

| Field | Detail |
| :--- | :--- |
| **Target System** | AZUKI-SL |
| **Attack Origin IP** | `88.97.178.12` |
| **Affected Directories/Files** | `C:\ProgramData\WindowsCache`, `export-data.zip` |

---

### Why (Motive)

| Field | Detail |
| :--- | :--- |
| **Likely Motive** | Financial (Theft of competitor intelligence). |
| **Target Value** | Pricing and supplier data (to undercut shipping contracts). |

---

### How (Attack Techniques)

| Field | Detail |
| :--- | :--- |
| **Initial Access Method** | Remote Desktop Protocol (RDP) with compromised credentials. |
| **Tools/Techniques Used** | `certutil.exe` (Download Utility Abuse), `mm.exe` (Credential Theft), `mstsc.exe` (Lateral Movement Tool). |
| **Persistence Method** | Scheduled Task: `Windows Update Check` and local user `support`. |
| **Data Collection Method** | Network reconnaissance using `ARP.EXE -a`, credential dumping, data archive to `export-data.zip`. |
| **Communication Method** | C2 via `78.141.196.6:443`, Exfiltration via `Discord`. |

## 3. Recommendations 

### Immediate Actions Needed:

1.  **Isolate Affected System:** Isolate the compromised system, **'AZUKI-SL'**, from all network segments immediately to prevent further lateral movement.
2.  **Remediate Accounts:** Reset the passwords for user **`kenji.sato`** and the newly created backdoor account **`support`**, then **disable** the `support` account.
3.  **Remediate Persistence & IOCs:** Remove the scheduled task **`Windows Update Check`** and delete all malicious files from `C:\ProgramData\WindowsCache`.

### Short-term Improvements (1-30 days):

1.  **Block IOCs:** Block all traffic to the C2 IP **`78.141.196.6`** and outbound connections to **`Discord`** at the perimeter firewall/proxy.
2.  **Audit Endpoints:** Audit the network for any other malicious activity from user **`kenji.sato`** and IP **`88.97.178.12`** on other endpoints.
3.  **Restore System:** Restore the affected system (**AZUKI-SL**) from a known clean backup dating **before Nov 19, 2025, 1:36 PM UTC**.

### Long-term Security Enhancements:

1.  **MFA Implementation:** Implement **Multi-Factor Authentication (MFA)** for all external remote access services (RDP/VPN).
2.  **Application Control:** Enforce Application Control or AppLocker policies to prevent the execution of utilities like **`certutil.exe`** and **`mm.exe`** from user-writable and temporary directories.
3.  **Log Management:** Configure Security Log retention policies or forward logs to a central **Security Information and Event Management (SIEM)** solution to prevent log tampering (e.g., via `SecurityLogCleared`).
