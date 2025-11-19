# Threat Hunt Capture the Flag — gab-intern-vm

**Author:** Monica Francis — First-time Capture the Flag threat hunt
**Timeframe Analyzed:** 2025-10-01 - 2025-10-15 UTC

## Quick Flags Reference

| Flag | Description | Evidence / Answer |
|------|-------------|-----------------|
| 1 | Initial Execution Detection | `-ExecutionPolicy` |
| 2 | Defense Disabling | `DefenderTamperArtifact.lnk` |
| 3 | Quick Data Probe | `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"` |
| 4 | Host Context Recon | `2025-10-09T12:51:44.3425653Z` |
| 5 | Storage Surface Mapping | `"cmd.exe" /c wmic logicaldisk get name,freespace,size` |
| 6 | Connectivity & Name Resolution Check | `RuntimeBroker.exe` |
| 7 | Interactive Session Discovery | `2533274790397065` |
| 8 | Runtime Application Inventory | `Tasklist.exe` |
| 9 | Privilege Surface Check | `2025-10-09T12:52:14.3135459Z` |
| 10 | Proof-of-Access & Egress Validation | `www.msftconnecttest.com` |
| 11 | Bundling / Staging Artifacts | `C:\Users\Public\ReconArtifacts.zip` |
| 12 | Outbound Transfer Attempt (Simulated) | `100.29.147.161` |
| 13 | Scheduled Re-Execution Persistence | `SupportToolUpdater` |
| 14 | Autorun Fallback Persistence | `RemoteAssistUpdater` |
| 15 | Planted Narrative / Cover Artifact | `SupportChat_log.lnk` |

---

## Scenario
A routine support request should have ended with a reset and reassurance. Instead, the so-called “help” left behind a trail of anomalies that don’t add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.
And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

**Mission:** Reconstruct the timeline, connect the scattered remnants of this "support session", and decide what was legitimate and what was staged.

---

## Starting Point

**Intel Provided:**
- Multiple machines spawned processes originating from download folders during the first half of October.
- Several machines shared similar executables, naming patterns, and traits.
- Common keywords: `desk`, `help`, `support`, `tool`.
- Intern-operated machines appear affected.

**Most Suspicious Machine:** `gab-intern-vm`

**KQL Used to Identify Suspicious Machine:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where FileName has_any ("desk", "help", "support", "tool")
| summarize SuspiciousFileCount = count(), DistinctFiles = dcount(FileName), FolderPaths = make_set(FolderPath) by DeviceName
| order by SuspiciousFileCount desc, DistinctFiles desc
```
<img width="468" height="79" alt="image" src="https://github.com/user-attachments/assets/a14c90b8-21a7-4c03-b5b3-833eda240e49" />

---

## Flags

<details>
<summary>Flag 1 — Initial Execution Detection</summary>

**Objective:** Detect the earliest anomalous execution that could represent an entry point.

**KQL Used:**
```kql
let VMName = "gab-intern-vm";
let startTime = datetime(2025-10-01);
let endTime = datetime(2025-10-15);
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between (startTime .. endTime)
| where InitiatingProcessCommandLine has ".cmd"
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```
<img width="468" height="56" alt="image" src="https://github.com/user-attachments/assets/271a9533-0a68-433b-a242-f124d9368e80" />

**Answer / Evidence:** `-ExecutionPolicy`

**Analyst Note:** Anchors the timeline; suspicious script execution from Downloads is a likely entry point.

</details>

<details>
<summary>Flag 2 — Defense Disabling</summary>

**Objective:** Identify staged security tampering attempts.

**KQL Used:**
```kql
let startTime = datetime(2025-10-01);
let endTime = datetime(2025-10-15);
DeviceFileEvents
| where Timestamp between (startTime .. endTime)
| where FileName has "DefenderTamperArtifact" or FolderPath has "DefenderTamperArtifact" or FileName has "SupportChat_log" or FileName has "SupportChat"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
```
<img width="468" height="82" alt="image" src="https://github.com/user-attachments/assets/cc0c8cfd-54cc-4b6e-8e2d-360123e2870f" />

**Answer / Evidence:** `DefenderTamperArtifact.lnk`

**Analyst Note:** Indicates intent to imply defenses were weakened.

</details>

<details>
<summary>Flag 3 — Quick Data Probe</summary>

**Objective:** Spot brief, opportunistic checks for readily available sensitive content.

**KQL Used:**
```kql
let VMName = "gab-intern-vm";
DeviceProcessEvents
| where DeviceName == VMName
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine contains "clip" or ProcessCommandLine contains " | clip" or ProcessCommandLine contains "Set-Clipboard" or ProcessCommandLine contains "Get-Clipboard"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
```
<img width="468" height="74" alt="image" src="https://github.com/user-attachments/assets/54b6292d-79dd-4c3b-99a2-0d064a871c4f" />

**Answer / Evidence:**
```text
"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"
```

**Analyst Note:** Clipboard reads are low-effort reconnaissance looking for credentials or sensitive data.

</details>

<details>
<summary>Flag 4 — Host Context Recon</summary>

**Objective:** Find activity that gathers basic host and user context to inform follow-up actions.

**KQL Used:**
```kql
let VM = "gab-intern-vm";
let startTime = datetime(2025-10-01);
let endTime = datetime(2025-10-15);
DeviceProcessEvents
| where Timestamp between (startTime .. endTime)
| where DeviceName == VM
| where ProcessCommandLine contains "qwi"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
```
<img width="468" height="66" alt="image" src="https://github.com/user-attachments/assets/8a1d4e0c-f697-4538-8b73-ae4cfff18c50" />

**Answer / Evidence:** Last recon attempt timestamp: `2025-10-09T12:51:44.3425653Z`

**Analyst Note:** Context gathering is key for next-step decisions.

</details>

<details>
<summary>Flag 5 — Storage Surface Mapping</summary>

**Objective:** Detect discovery of local or network storage locations.

**KQL Used:**
```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where Timestamp between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("fsutil", "wmic logicaldisk", "Get-PSDrive", "Get-Volume", "Get-ChildItem -Path", "dir /s", "du ", "diskfree", "net share", "net use")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
```
<img width="468" height="43" alt="image" src="https://github.com/user-attachments/assets/062879f1-b003-4788-9d58-7a5a16fa4f2e" />

**Answer / Evidence:** `"cmd.exe" /c wmic logicaldisk get name,freespace,size`

**Analyst Note:** Determines where data might reside for collection.

</details>

<details>
<summary>Flag 6 — Connectivity & Name Resolution Check</summary>

**Objective:** Identify checks that validate network reachability and name resolution.

**KQL Used:**
```kql
let t = datetime(2025-10-09T12:51:44.3425653Z);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where Timestamp between (t - 10m .. t + 10m)
| where ProcessCommandLine contains "clip" or ProcessCommandLine contains " | clip" or ProcessCommandLine contains "Set-Clipboard" or ProcessCommandLine contains "Get-Clipboard"
| project Timestamp, ProcessId, FileName, ProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp asc
```
<img width="468" height="56" alt="image" src="https://github.com/user-attachments/assets/5a26a8d0-9523-488e-852b-81530103405e" />

**Answer / Evidence:** `RuntimeBroker.exe`

**Analyst Note:** A user-context process was leveraged for networking checks.

</details>

<details>
<summary>Flag 7 — Interactive Session Discovery</summary>

**Objective:** Reveal attempts to detect interactive or active user sessions.

**KQL Used:**
```kql
let VM = "gab-intern-vm";
let t = datetime(2025-10-09T12:51:00Z);
DeviceProcessEvents
| where DeviceName == VM
| where Timestamp between (t - 10m .. t + 10m)
| where ProcessCommandLine has "qwinsta" or FileName has "qwinsta" or ProcessCommandLine has "query user"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessUniqueId
| order by Timestamp asc
```
<img width="468" height="63" alt="image" src="https://github.com/user-attachments/assets/447ac40f-77e5-451d-821b-61590dbb8a90" />

**Answer / Evidence:** `2533274790397065`

**Analyst Note:** Helps map active sessions for potential monitoring.

</details>

<details>
<summary>Flag 8 — Runtime Application Inventory</summary>

**Objective:** Detect enumeration of running applications and services.

**KQL Used:**
```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("tasklist","Get-Process","wmic process","Get-Service","sc query","net start","Get-CimInstance","Get-WmiObject -Class Win32_Process")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp desc
| take 50
```
<img width="468" height="49" alt="image" src="https://github.com/user-attachments/assets/b3975583-396e-4a24-9574-a93934b39e99" />

**Answer / Evidence:** `Tasklist.exe`

**Analyst Note:** Enumerates processes and services for targeting decisions.

</details>

<details>
<summary>Flag 9 — Privilege Surface Check</summary>

**Objective:** Detect attempts to understand available privileges.

**KQL Used:**
```kql
let VM="gab-intern-vm";
let startTime=datetime(2025-10-01);
let endTime=datetime(2025-10-15);
DeviceProcessEvents
|where DeviceName==VM and Timestamp between(startTime..endTime)
|where ProcessCommandLine has_any("whoami","whoami /groups","whoami /all","net user","net localgroup","Get-LocalUser","Get-LocalGroupMember","Get-ADUser","Get-ADPrincipalGroupMembership","Get-LocalGroup","whoami /priv","/priv","SeDebugPrivilege","TokenElevation","Get-ProcessToken","whoami /groups")
|project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
|order by Timestamp asc
|take 1
```
<img width="468" height="79" alt="image" src="https://github.com/user-attachments/assets/140dc0d3-0753-46a2-91ce-d1d7f4b3c4c4" />

**Answer / Evidence:** `2025-10-09T12:52:14.3135459Z`

**Analyst Note:** Early privilege checks determine escalation or lateral movement potential.

</details>

<details>
<summary>Flag 10 — Proof-of-Access & Egress Validation</summary>

**Objective:** Validate outbound connectivity and host access.

**KQL Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09) .. datetime(2025-10-10))
| where RemotePort in (80, 443)
| where InitiatingProcessFileName has_any ("powershell.exe","cmd.exe")
| project TimeGenerated, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="468" height="100" alt="image" src="https://github.com/user-attachments/assets/45e49121-6b06-4aef-9379-b70e76b1c2e9" />

**Answer / Evidence:** `www.msftconnecttest.com`

**Analyst Note:** Simple HTTP checks confirm outbound capability.

</details>

<details>
<summary>Flag 11 — Bundling / Staging Artifacts</summary>

**Objective:** Detect consolidation of artifacts for transfer.

**KQL Used:**
```kql
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where ActionType == "FileCreated"
| where Timestamp between (datetime(2025-10-09) .. datetime(2025-10-11))
| where FileName endswith ".zip"
| project Timestamp, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1
| order by Timestamp asc
```
<img width="468" height="101" alt="image" src="https://github.com/user-attachments/assets/60ce2d74-a9d1-4f61-9073-fe5980407878" />

**Answer / Evidence:** `C:\Users\Public\ReconArtifacts.zip`

**Analyst Note:** Staging makes artifacts ready for exfiltration.

</details>

<details>
<summary>Flag 12 — Outbound Transfer Attempt (Simulated)</summary>

**Objective:** Identify attempted or simulated exfiltration.

**KQL Used:**
```kql
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:57:00Z) .. datetime(2025-10-09T13:05:00Z))
| project TimeGenerated, RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="468" height="102" alt="image" src="https://github.com/user-attachments/assets/990e215c-e335-4db5-a135-1515939f3506" />

**Answer / Evidence:** Last unusual outbound IP: `100.29.147.161`

**Analyst Note:** Timing aligns with staged `ReconArtifacts.zip` upload attempt.

</details>

<details>
<summary>Flag 13 — Scheduled Re-Execution Persistence</summary>

**Objective:** Detect recurring execution setup for persistence.

**KQL Used:**
```kql
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T13:10:00Z))
| where InitiatingProcessFileName =~ "powershell.exe" or InitiatingProcessFileName =~ "cmd.exe"
| where ProcessCommandLine contains "schtasks" or ProcessCommandLine contains "/create"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="468" height="69" alt="image" src="https://github.com/user-attachments/assets/8fefd04e-5ecf-4318-93b1-50ecdb52ed6e" />

**Answer / Evidence:** `SupportToolUpdater`

**Analyst Note:** Scheduled task ensures the actor can return.

</details>

<details>
<summary>Flag 14 — Autorun Fallback Persistence</summary>

**Objective:** Spot lightweight autorun entries in user scope.

**KQL Used (example registry query):**
```kql
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:50:00Z) .. datetime(2025-10-09T13:20:00Z))
| where RegistryKey has_any ("\\Run\\", "\\RunOnce\\") or RegistryValueName has_any ("RemoteAssistUpdater","SupportToolUpdater")
| project Timestamp = TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessAccountName
| order by Timestamp asc
```

**Answer / Evidence:** `RemoteAssistUpdater`

**Analyst Note:** Redundant persistence ensures continued execution.

</details>

<details>
<summary>Flag 15 — Planted Narrative / Cover Artifact</summary>

**Objective:** Identify a narrative artifact intended to justify suspicious activity.

**KQL Used:**
```kql
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:55:00Z) .. datetime(2025-10-09T13:10:00Z))
| where ActionType in ("FileCreated", "FileModified")
| where InitiatingProcessFileName in ("notepad.exe", "explorer.exe")
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, ActionType
| order by TimeGenerated asc
```
<img width="468" height="114" alt="image" src="https://github.com/user-attachments/assets/bb35dcb7-3379-4795-a7eb-10d4ac60f915" />

**Answer / Evidence:** `SupportChat_log.lnk`

**Analyst Note:** A support chat log shortcut provides a plausible narrative to explain the behavior.

</details>

---

## Analyst Reasoning / Logical Flow

1. Suspicious script in Downloads initiates timeline.
2. Defense tampering attempts are staged.
3. Quick clipboard probe for opportunistic data.
4. Host context recon determines user/environment.
5. Storage enumeration identifies data locations.
6. Network checks confirm egress.
7. Session enumeration maps active users.
8. Runtime process inventory shows running applications.
9. Privilege checks determine escalation potential.
10. Staging artifacts into public folder prepares for exfiltration.
11. Simulated outbound HTTP request tests exfil capability.
12. Scheduled task and autorun registry key ensure persistence.
13. Planted support chat artifact provides cover story.
