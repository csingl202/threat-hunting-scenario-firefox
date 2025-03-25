 # Threat Event (Suspicious Firefox Behavior)
**Unauthorized Firefox Browser Installation and Use**

 ## Steps the "Bad Actor" took to Create Logs and IoCs:
1. Download the Firefox browser installer: https://www.mozilla.org/en-US/firefox/windows/
2. Install it manually: ```c:\users\sand\Downloads```
3. Opens the Firefox browser on the desktop
4. Connect to Firefox and browse a few sites.
   - Malicious site: ```http://malicious-website.com```
   - Malicious site: ```http://example.com/shell.php```
6. Create a file within the Programdata folder called ```eicar.ps1``` using PowerShell.
7. Made an unsuccessful attempt to download a file named ```exploit-kit.zip``` using PowerShell.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting Firefox download and installation.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the launch of Firefox as well as the PowerShell activity.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect Firefox browsing activity, specifically firefox.exe making connections over known ports ( 80, 443).|

---

## Related Queries:
```kql
// Installer name == firefox-(version).exe
// Detect the installer being downloaded
DeviceFileEvents
| where FileName startswith "firefox"
| where DeviceName == "newtra"
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessAccountName, InitiatingProcessFileName

// Firefox Browser being installed
DeviceProcessEvents
| where DeviceName == "newtra"
| where InitiatingProcessCommandLine contains "launched"
| where FileName contains "firefox"
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine

// PowerShell file was successfully installed while another attempt to download a file was unsuccessful
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

// Firefox Browser being launched
DeviceProcessEvents
| where DeviceName == "newtra"
| where InitiatingProcessCommandLine contains "launched"
| where FileName contains "firefox"
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine

// Firefox Browser being used and actively creating network connections
DeviceNetworkEvents  
| where DeviceName == "newtra"  
| where InitiatingProcessAccountName != "system" 
|where InitiatingProcessFileName in ("firefox.exe", "powershell.exe")
| where RemotePort in ("80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc


// Eicar file was created
DeviceFileEvents
| where FileName contains "eicar.ps1"
| where DeviceName == "newtra"
```

---

## Created By:
- **Author Name**: Clyde Singleton
- **Author Contact**:  https://github.com/csingl202
- **Date**: March 25, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March 25, 2025`| `Clyde Singleton`   
