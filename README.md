# threat-hunting-scenario-tor


#  Threat Hunt Report: Unauthorized TOR Usage

---

## Scenario Creation

### Platforms and Technologies Leveraged

- Windows Virtual Machine (Azure)
- Microsoft Defender for Endpoint
- Advanced Hunting (KQL)
- TOR Browser Portable

---

## Scenario

During routine monitoring, encrypted outbound traffic patterns were observed originating from an internal endpoint. Due to the nature of the traffic, there was concern that anonymization software may have been installed and used to bypass network visibility controls.

The goal of this investigation was to:

- Identify whether TOR Browser was downloaded
- Confirm execution of the installer
- Detect TOR runtime process activity
- Validate outbound connections to known TOR relay ports
- Construct a structured event timeline
- Document findings and response actions

---

# High-Level TOR IoC Discovery Plan

The following telemetry tables were analyzed:

- `DeviceFileEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`

---

# Steps Taken

---

## 1️⃣ Searched the DeviceFileEvents Table

The investigation began by identifying TOR-related file activity on the endpoint.

### Query Used

```kql
DeviceFileEvents
| where DeviceName == "<YOUR_VM_NAME>"
| where InitiatingProcessAccountName == "<YOUR_USERNAME>"
| where FileName contains "tor"
| order by Timestamp desc
```

### Findings

- Identified TOR installer download
- Observed rename from temporary browser download file
- Confirmed installer storage location
- Captured file hash values
- Verified initiating user account

### File Details

- **File Name:**  
- **Folder Path:**  
- **SHA1:**  
- **SHA256:**  
- **File Size:**  
- **Initiating Account:**  

This confirmed that the TOR installer was successfully downloaded to the system.

---

## 2️⃣ Searched the DeviceProcessEvents Table (Installer Execution)

After confirming download activity, process telemetry was reviewed to determine whether the installer was executed.

### Query Used

```kql
DeviceProcessEvents
| where DeviceName == "<YOUR_VM_NAME>"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```

### Findings

- Detected execution of the TOR installer
- Confirmed execution under user context
- Identified command-line arguments (if applicable)
- Verified execution path

This step confirmed that TOR Browser was installed on the endpoint.

---

## 3️⃣ Searched the DeviceProcessEvents Table (TOR Runtime Execution)

To confirm that TOR was actively launched after installation, additional process telemetry was analyzed.

### Query Used

```kql
DeviceProcessEvents
| where DeviceName == "<YOUR_VM_NAME>"
| where FileName in~ ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
```

### Findings

- Observed execution of `tor.exe`
- Identified TOR-modified `firefox.exe`
- Confirmed parent-child process relationships
- Verified execution directory within the TOR installation folder

This indicates that the TOR Browser was successfully launched.

---

## 4️⃣ Searched the DeviceNetworkEvents Table (TOR Network Connections)

To validate active TOR usage, outbound network telemetry was reviewed for known TOR relay ports.

### Query Used

```kql
DeviceNetworkEvents
| where DeviceName == "<YOUR_VM_NAME>"
| where InitiatingProcessFileName in~ ("tor.exe","firefox.exe")
| where RemotePort in (9001, 9030, 9050, 9150, 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### Findings

- Detected outbound connections associated with TOR processes
- Observed encrypted traffic over common TOR relay ports
- Confirmed successful connection events
- Identified remote IP addresses consistent with TOR activity

This confirms traffic was routed through the TOR network.

---

# Chronological Event Timeline

> *(Insert your own timestamps and exact values below.)*

---

## 1. TOR Installer Download

- **Timestamp:**  
- **Event:**  
- **File Path:**  
- **Action Observed:**  

---

## 2. TOR Installer Execution

- **Timestamp:**  
- **Process Executed:**  
- **Command Line:**  
- **Execution Path:**  

---

## 3. TOR Browser Launch

- **Timestamp:**  
- **Processes Observed:**  
- **Parent Process:**  
- **Installation Directory:**  

---

## 4. TOR Network Activity

- **Timestamp:**  
- **Remote IP:**  
- **Remote Port:**  
- **Action Type:**  

---

# Summary

The investigation confirmed that TOR Browser was downloaded, installed, and executed on the monitored endpoint.

Evidence supporting this conclusion includes:

- Verified TOR installer download activity
- Confirmed execution of the installer
- Detection of TOR runtime processes
- Observed outbound connections consistent with TOR network behavior

The collected telemetry indicates intentional use of anonymization software on the system.

---

# Response Taken

- Activity documented for review
- Endpoint flagged for monitoring
- Management notified (if applicable)
- Detection logic recommended for ongoing monitoring

---

# Detection Recommendations

### Process-Based Detection

```kql
DeviceProcessEvents
| where FileName in~ ("tor.exe")
or ProcessCommandLine contains "tor-browser"
```

### Network-Based Detection

```kql
DeviceNetworkEvents
| where RemotePort in (9001,9030,9050,9150)
```

---
