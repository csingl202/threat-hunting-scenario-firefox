 ![image](https://github.com/user-attachments/assets/a4ad0cc4-1c10-46ab-9531-762eb2db0afb)


# Threat Hunt Report: Suspicious Firefox Behavior
- [Scenario Creation](https://github.com/csingl202/threat-hunting-scenario-firefox/blob/main/Threat_Event_(Firefox%20Usage).md )

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

### 3. Searched the `DeviceProcessEvents` Table for Firefox Browser Execution

Searched for any indication that user "sand" actually opened the Firefox browser. There was evidence that they did open it at `2025-03-24T21:30:01.6600135Z`. I also searched for any indication of unusual PowerShell activity, and  quickly discovered the following: (1) an attempt to download a file named 'exploit-kit.zip', and (2) the downloading and installation of a file named 'eicar.ps1'.

**Query used to locate events:**

```kql

DeviceProcessEvents
| where DeviceName == "newtra"
| where InitiatingProcessCommandLine contains "launched"
| where FileName contains "firefox"
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine

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

![image](https://github.com/user-attachments/assets/d467e8a1-8af3-4163-a6c7-b3dc52c6a8e5)

![image](https://github.com/user-attachments/assets/9517c3d6-cb51-4617-9b72-ab22e7415414)

![image](https://github.com/user-attachments/assets/1999823a-1e12-4f89-aa54-72d8633496d8)

---

### 4. Searched the `DeviceNetworkEvents` Table for Firefox Browser Activity (malicious websites)

Searched for any indication the Firefox browser was used to establish a connection using any of the known ports. At `2025-03-24T22:30:40.5748365Z`, an employee on the "newtra" device successfully established a connection to the remote IP address `91.195.240.94` on port `80`. The connection was initiated by the process `firefox.exe`, located in the folder `C:\Program Files\Mozilla Firefox`. There were a couple of other connections to sites over port `443` and port '80'.

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

### 1. File Download - Firefox Installer

- **Timestamp:** `2025-03-24T21:28:51.0902097Z`
- **Event:** The user "sand" downloaded a file named `firefox.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\sand\Downloads`

### 2. Process Execution - Firefox Browser Installation

- **Timestamp:** `2025-03-24T21:30:01.6600135Z`
- **Event:** The user "sand" executed the file `firefox.exe` within the Downloads folder.
- **Action:** Process creation detected.
- **Command:** .manually installed from the Downloads folder.
- **File Path:** `C:\Program Files\Mozilla Firefox`

### 3. Process Execution - Firefox Browser Launch

- **Timestamp:** `2025-03-24T21:30:01.6600135Z`
- **Event:** User "sand" opened the Firefox browser. Subsequent processes associated with the Firefox browser, such as `firefox.exe` was also created, indicating that the browser launched successfully.
- **Action:** Process creation of Firefox browser-related executables detected.
- **File Path:** `c:\users\sand\appdata\local\temp\7zs443a6f18\setup.exe`

### 4. Network Connection - Firefox Browser Activity (malicious websites)

- **Timestamp:** `2025-03-24T22:30:40.5748365Z`
- **Event:** A network connection to IP `91.195.240.94` on port `80` by user "sand" was established using `firefox.exe`, confirming Firefox browser network activity.
- **Action:** Connection success.
- **Process:** `firefox.exe`
- **File Path:** `c:\program files\mozilla firefox\firefox.exe`

### 5. Additional Network Connections - Firefox Browser Activity (malicious websites)

- **Timestamps:**
  - `2025-03-24T22:30:53.1543691Z` - Connected to `91.195.240.94 on port `443`.
  - `2025-03-24T22:29:22.5670717Z` - Local connection to `23.192.228.80` on port `80`.
- **Event:** Additional Firefox network connections were established, indicating ongoing activity by user "sand" through the Firefox browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - Eicar.ps1

- **Timestamp:** `2025-03-24T22:37:54.8077093Z`
- **Event:** The user "sand" created a file named `eicar.ps1` within the Programdata folder using PowerShell, potentially testing for the presence of anti-virus software.
- **Action:** File creation detected.
- **File Path:** `C:\programdata\eicar.ps1`

---

## Summary

The user "sand" on the "newtra" device initiated and completed the installation of the Firefox browser. The employee then proceeded to launch the browser, establish connections using Firefox, and create a file named `eicar.ps1` using PowerShell. Additionally, an attempt to download a file named 'exploit-kit.zip' using PowerShell was also made; however, the attempt was unsuccessful.  These activities indicate that the user actively installed Firefox; thereafter, the user began using Firefox and PowerShell to potentially install malicious software.

---

## Response Taken

Firefox and PowerShell usage was confirmed on the endpoint "newtra" by the user "sand". The device was isolated using Microsoft Defender for Endpoint, and the user's direct manager was notified.

---
