# Azure-Sysmon-Telemetry-and-Detection-Engineering
## Overview

This project demonstrates the design and implementation of a host-level telemetry and detection engineering pipeline in Azure.

The objective was not to “collect logs,” but to:

- Engineer structured telemetry from a cloud-hosted Windows VM

- Normalize and parse raw Sysmon XML data in Log Analytics

- Correlate network activity, process execution, and authentication failures

- Develop threshold-based brute-force detection logic

- Operationalize the detection as a scheduled query rule

The result is a reproducible detection engineering workflow that identifies real-world SSH attack activity against exposed infrastructure.

## Architecture

### Azure Subscription

→ Resource Group

→ Windows Server VM (Public IP enabled for SSH exposure)

→ Sysmon (Event ID 1 & 3 enabled)

→ Data Collection Rule

→ Log Analytics Workspace

→ Custom KQL Correlation & Detection Rule

This architecture intentionally separates:

- Host telemetry generation

- Log ingestion and normalization

- Detection logic

- Alert operationalization

## Telemetry Engineering
### Sysmon Configuration

Sysmon was deployed with configuration enabling:

- Event ID 1 — Process Creation

- Event ID 3 — Network Connections

These events provide:

- Process GUID correlation

- Command-line visibility

- Source and destination IP tracking

- Port and protocol insight

Logs were forwarded via Azure Monitor Agent using a custom Data Collection Rule targeting:

**`Microsoft-Windows-Sysmon/Operational`**

## Log Ingestion Validation

Raw Sysmon events are ingested into the Event table.

Initial validation query:
```kql
Event
| where EventID == 3
| take 10
```
The relevant telemetry fields are embedded inside **`ParameterXml`**, requiring explicit parsing.

## Parsing Raw Sysmon XML

Because Sysmon parameters are stored as indexed **`<Param>`** values, structured extraction is required.

```kql
Event
| where EventID == 3
| extend ParamXml = parse_xml(ParameterXml)
| extend
    ProcessGuid = tostring(ParamXml.Param[2]),
    Image = tostring(ParamXml.Param[4]),
    User = tostring(ParamXml.Param[5]),
    Protocol = tostring(ParamXml.Param[6]),
    SourceIp = tostring(ParamXml.Param[9]),
    DestinationIp = tostring(ParamXml.Param[14]),
    DestinationPort = tostring(ParamXml.Param[16])
| project TimeGenerated, SourceIp, DestinationIp, DestinationPort, Image, Protocol
```

This converts raw XML into structured fields suitable for hunting and detection.

## Observed External Attack Activity

Live telemetry captured external SSH scanning activity:

- External Source IP targeting port 22

- Process handling connection: sshd.exe

- Protocol: TCP

- Destination: Azure VM internal IP

This confirms real-world exposure and validates the telemetry pipeline.

## Correlation: Network Activity → Authentication Failures

This section demonstrates advanced threat-hunting by correlating Sysmon and Windows Security events. It establishes:

- Which process accepted or initiated the network connection (Event 3)  
- The command-line context and parent/child process relationships involved (Event 1)  
- User accounts targeted by failed logons (Event 4625)  
- Temporal correlation of events to identify suspicious behavior and potential brute-force attacks  



```kql
// Capture network connections (Event 3) and process creations (Event 1) from Sysmon 
Event
| where EventID == 1 or EventID == 3
| extend ParamXml = parse_xml(ParameterXml)
| extend
    EventType = case(EventID == 1, "ProcessCreation", EventID == 3, "NetworkConnection", "Other"),
    ProcessGuid = tostring(ParamXml.Param[2]),
    SourceIp = iif(EventID == 3, tostring(ParamXml.Param[9]), ""),
    DestinationPort = iif(EventID == 3, tostring(ParamXml.Param[16]), ""),
    ProcessName = iif(EventID == 3, tostring(ParamXml.Param[4]), ""),
    CommandLine = iif(EventID == 1, tostring(ParamXml.Param[10]), "")
| summarize Events=count(), min(TimeGenerated), max(TimeGenerated) 
          by EventType, ProcessGuid, SourceIp, DestinationPort, ProcessName, CommandLine
| order by max_TimeGenerated desc
```
Sample Result:

ProcessCreation → {29c9e563-27de-69a7-db08-000000000700}

ProcessName → C:\Windows\System32\OpenSSH\sshd.exe

CommandLine → "C:\Windows\System32\OpenSSH\sshd.exe" -y

Events Count → 1

TimeGenerated → 2026-03-03T18:26:38.2173536Z


```kql
// Query 2 – Failed Logon Events (SecurityEvent 4625)
Event
| where EventID == 4625
| extend XmlData = parse_xml(tostring(EventData))
| extend TargetUserName = tostring(XmlData.Event.EventData.Data[5]),
         Status = tostring(XmlData.Event.EventData.Data[8])
| summarize FailedAttempts = count() by TargetUserName, Status, bin(TimeGenerated, 5m)
| order by TimeGenerated desc
```
Sample Result:

TimeGenerated → 2026-03-03T18:20:00Z

TargetUserName → NOUSER

FailedAttempts → 56


## Detection Engineering

The following detection logic was implemented:

Trigger alert when:

- ≥ 20 SSH connection attempts

- AND ≥ 10 failed logons

- Within a 15-minute window

```kql
let TimeWindow = 15m;

let FailedLogons =
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(TimeWindow)
| summarize FailedAttempts = count() by IpAddress;

let SSHConnections =
Event
| where EventID == 3
| where TimeGenerated > ago(TimeWindow)
| extend ParamXml = parse_xml(ParameterXml)
| extend
    SourceIp = tostring(ParamXml.Param[9]),
    DestinationPort = tostring(ParamXml.Param[16])
| where DestinationPort == "22"
| summarize ConnectionAttempts = count() by SourceIp;

SSHConnections
| join kind=inner FailedLogons on $left.SourceIp == $right.IpAddress
| where ConnectionAttempts >= 20 and FailedAttempts >= 10
```

This query was deployed as a scheduled query rule in Azure Monitor.

## Security Engineering Considerations

This implementation emphasizes:

- Structured telemetry ingestion

- Explicit XML normalization

- Cross-event correlation via ProcessGuid

- Signal-to-noise reduction through threshold logic

- Operationalization into alerting

The approach mirrors production detection engineering workflows rather than ad-hoc log queries.

## Key Competencies Demonstrated

- Azure infrastructure deployment

- Host-level telemetry engineering

- Azure Monitor Agent and Data Collection Rules

- Log Analytics schema normalization

- Advanced KQL parsing and joins

- Threat hunting methodology

- Detection engineering lifecycle

- Cloud-based brute-force identification

## Next Iteration

Future expansions of this work will integrate:

- Microsoft Sentinel analytic rules

- Incident automation playbooks

- Identity attack surface analysis

- Defender for Cloud integration

- NSG and network segmentation redesign

This project reflects a structured approach to building visibility, correlating telemetry, and translating signal into actionable detection logic within Azure.
