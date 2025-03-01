---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-unusual-child-process-from-a-system-virtual-process.html
---

# Unusual Child Process from a System Virtual Process [prebuilt-rule-8-17-4-unusual-child-process-from-a-system-virtual-process]

Identifies a suspicious child process of the Windows virtual system process, which could indicate code injection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 313

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4816]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Child Process from a System Virtual Process**

In Windows environments, the System process (PID 4) is a critical component responsible for managing system-level operations. Adversaries may exploit this by injecting malicious code to spawn unauthorized child processes, evading detection. The detection rule identifies anomalies by flagging unexpected child processes originating from the System process, excluding known legitimate executables, thus highlighting potential threats.

**Possible investigation steps**

* Review the process details of the suspicious child process, including the executable path and command line arguments, to determine if it matches known malicious patterns or anomalies.
* Check the parent process (PID 4) to confirm it is indeed the System process and verify if any legitimate processes are excluded as per the rule (e.g., Registry, MemCompression, smss.exe).
* Investigate the timeline of events leading up to the process start event to identify any preceding suspicious activities or anomalies that might indicate process injection or exploitation.
* Correlate the alert with other security telemetry from data sources like Microsoft Defender for Endpoint or Sysmon to identify any related alerts or indicators of compromise.
* Examine the network activity associated with the suspicious process to detect any unauthorized connections or data exfiltration attempts.
* Consult threat intelligence sources to determine if the process executable or its behavior is associated with known malware or threat actor techniques.
* If necessary, isolate the affected system to prevent further potential malicious activity and conduct a deeper forensic analysis.

**False positive analysis**

* Legitimate system maintenance tools may occasionally spawn child processes from the System process. Users should monitor and verify these tools and add them to the exclusion list if they are confirmed to be safe.
* Some security software might create child processes from the System process as part of their normal operation. Identify these processes and configure exceptions to prevent unnecessary alerts.
* Windows updates or system patches can sometimes trigger unexpected child processes. Ensure that these processes are part of a legitimate update cycle and exclude them if they are verified.
* Custom scripts or administrative tools used for system management might also cause false positives. Review these scripts and tools, and if they are deemed safe, add them to the exclusion list.
* Virtualization software or sandbox environments may mimic or interact with the System process in ways that trigger alerts. Validate these interactions and exclude them if they are part of normal operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread of the potential threat.
* Terminate any suspicious child processes identified as originating from the System process (PID 4) that are not part of the known legitimate executables.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any injected malicious code.
* Review recent system changes and installed software to identify any unauthorized modifications or installations that could have facilitated the process injection.
* Restore the system from a known good backup if malicious activity is confirmed and cannot be fully remediated through other means.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for the affected system and similar environments to detect any recurrence of the threat, focusing on process creation events and anomalies related to the System process.


## Rule query [_rule_query_5771]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.parent.pid == 4 and process.executable : "?*" and
  not process.executable : ("Registry", "MemCompression", "?:\\Windows\\System32\\smss.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)



