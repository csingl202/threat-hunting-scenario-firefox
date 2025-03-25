 ![image](https://github.com/user-attachments/assets/a4ad0cc4-1c10-46ab-9531-762eb2db0afb)


# Threat Hunt Report: Suspicious Firefox Behavior
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Firefox browser

##  Scenario

The latest cybersecurity news report has indicated that there are new vulnerabilities in FireFox which could be exploited by attackers.  Specifically, an unpatched vulnerability (CVE-2025-12345) has been found in Firefox that allows attackers to bypass certain security mechanisms and execute arbitrary code.  Given that this vulnerability is actively being exploited in the wild, it is crucial to check for any signs of malicious activity using the Firefox browser on corporate endpoints.  Additionally, when bad actors gain access to a system, they will attempt to download malicious payloads or tools directly from the internet to expand their control or establish persistence.  This is often achieved using legitimate system utilities like PowerShell to blend in with normal activity.
Consequently, management has decided to check the network logs for any unexpecting Firefox traffic patterns or node connections to any unauthorized endpoints.  The goal is to detect any abnormal Firefox and PowerShell usage, and analyze related security incidents to mitigate potential risks. If any questionable behavior is discovered, management will be informed.

### High-Level Firefox-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or abnormal activity.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "firefox" in it and discovered what looks like the user "sand" downloaded a Firefox installer on the desktop.  These events began at `2025-03-24T21:28:51.0902097Z`.

**Query used to locate events:**

```kql

DeviceFileEvents
| where FileName startswith "firefox"
| where DeviceName == "newtra"
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
```
![image](https://github.com/user-attachments/assets/5e06eb78-2891-409e-bdd4-0a6e2fedf499)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "launched". Based on the logs returned, at `2025-03-24T21:30:01.6600135Z`, an employee on the "newtra" device ran a file named 'firefox.exe` from their Downloads folder.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "newtra"
| where InitiatingProcessCommandLine contains "launched"
| where FileName contains "firefox"
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
 
```
![image](https://github.com/user-attachments/assets/d467e8a1-8af3-4163-a6c7-b3dc52c6a8e5)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "sand" actually opened the Firefox browser. There was evidence that they did open it at `2025-03-24T21:30:01.6600135Z`. I also searched for any indication of unusual PowerShell activity, and discovered the following There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "newtra" 
| where AccountName == "sand"                                                                                
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "ps1"                                                              
| project DeviceName, AccountName, FileName, ProcessCommandLine

DeviceProcessEvents
| where DeviceName == "newtra" 
| where AccountName == "sand"                                                                                
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "zip"                                                              
| project DeviceName, AccountName, FileName, ProcessCommandLine

```
![image](https://github.com/user-attachments/assets/9517c3d6-cb51-4617-9b72-ab22e7415414)

![image](https://github.com/user-attachments/assets/1999823a-1e12-4f89-aa54-72d8633496d8)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "newtra"  
| where InitiatingProcessAccountName != "system" 
|where InitiatingProcessFileName in ("firefox.exe", "powershell.exe")
| where RemotePort in ("80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/50f8d756-b59d-4c83-a886-0e6cf9e8ceef)



---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-03-24T21:28:51.0902097Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\sand\Downloads`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-03-24T21:30:01.6600135Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Program Files\Mozilla Firefox`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-03-24T21:32:37.7259964Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `c:\users\sand\appdata\local\temp\7zs443a6f18\setup.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-03-24T22:30:40.5748365Z`
- **Event:** A network connection to IP `91.195.240.94` on port `80` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `firefox.exe`
- **File Path:** `c:\program files\mozilla firefox\firefox.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-03-24T22:30:53.1543691Z` - Connected to `91.195.240.94 on port `443`.
  - `2025-03-24T22:29:22.5670717Z` - Local connection to `23.192.228.80` on port `80`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-03-24T22:37:54.8077093Z`
- **Event:** The user "employee" created a file named `eicar.ps1` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\programdata\eicar.ps1`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
