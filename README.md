# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Colby-hin/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "thl-colby"
| where InitiatingProcessAccountName == "azureuser"
| where FileName startswith "tor"
| where Timestamp >= datetime(Feb 22, 2026 8:08:47 PM)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1471" height="681" alt="image" src="https://github.com/user-attachments/assets/1e4efb8a-74d7-476c-a92b-63ae0de499a3" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "thl-colby"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.6.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1828" height="634" alt="image" src="https://github.com/user-attachments/assets/bee743ec-27c2-45f9-9fea-bb86cff36d5e" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "thl-colby"
| where FileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
<img width="1049" height="716" alt="image" src="https://github.com/user-attachments/assets/07eea8c0-8b5b-47cf-9eb6-a92799534974" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "thl-colby"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 
```
<img width="1057" height="794" alt="image" src="https://github.com/user-attachments/assets/a4ac6dcb-4ec4-4e38-8fac-b79768530ca8" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

Timeframe: Starting at Feb 22, 2026 8:08:47 PM
 What Happened:
 A search of the DeviceFileEvents table revealed multiple file events containing the string “tor” initiated by azureuser on the device thl-colby.
 This activity indicates that the user downloaded a TOR installer and that TOR-related files were created or copied to the Desktop.
The investigation at this stage confirmed that:
A TOR installer was downloaded


Files with “tor” in the name were created on the device


A file called tor-shopping-list.txt was created on the Desktop


### 2. Process Execution - TOR Browser Installation

Timestamp: Feb 22, 2026 8:13:03 PM
 What Happened:
 The portable TOR Browser installer (tor-browser-windows-x86_64-portable-15.0.6.exe) was executed by azureuser from the Downloads folder.
 The installer was launched with a silent install flag (/S), indicating a quiet install process without user prompts.
This confirms that the TOR Browser installation was executed.


### 3. Process Execution - TOR Browser Launch

Timestamp (Observed): 2026-02-23T01:13:56.1645318Z
 What Happened:
 Process telemetry shows that executable(s) associated with the actual TOR Browser (such as tor.exe or firefox.exe) were launched. This indicates that the TOR Browser was opened and run after installation.
This suggests that the user did not just install the browser — they actively launched it and began a session.


### 4. Network Connection - TOR Network

Timestamp (Observed): 2026-02-23T01:14:16.9136841Z
 What Happened:
 Network telemetry shows that a successful outbound connection was established from the endpoint thl-colby using tor.exe. The connection went to:
Remote IP: 89.117.1.123


Remote Port: 9001


Initiating Process: tor.exe


Folder Path: c:\users\azureuser\desktop\tor browser\browser\torbrowser\tor\tor.exe


This connection was made over a known TOR process and a known TOR network port, confirming that the TOR Browser was not only launched, but used to connect to the TOR network.


---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `thl-colby` by the user `azureuser`. The device was isolated, and the user's direct manager was notified.

---


