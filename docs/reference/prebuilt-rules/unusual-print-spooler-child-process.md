---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-print-spooler-child-process.html
---

# Unusual Print Spooler Child Process [unusual-print-spooler-child-process]

Detects unusual Print Spooler service (spoolsv.exe) child processes. This may indicate an attempt to exploit privilege escalation vulnerabilities related to the Printing Service on Windows.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.*
* logs-system.security*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Data Source: System
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1143]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Print Spooler Child Process**

The Print Spooler service, integral to Windows environments, manages print jobs and interactions with printers. Adversaries may exploit vulnerabilities in this service to escalate privileges, gaining unauthorized access or control. The detection rule identifies suspicious child processes spawned by the Print Spooler, excluding known legitimate processes, to flag potential exploitation attempts, focusing on unusual command lines and integrity levels.

**Possible investigation steps**

* Review the process details to identify the unusual child process spawned by spoolsv.exe, focusing on the process name and command line arguments to understand its purpose and potential malicious intent.
* Check the integrity level of the process using the fields process.Ext.token.integrity_level_name or winlog.event_data.IntegrityLevel to confirm if it is running with elevated privileges, which could indicate an exploitation attempt.
* Investigate the parent-child relationship by examining the process tree to determine if there are any other suspicious processes associated with the same parent process, spoolsv.exe.
* Cross-reference the process executable path against known legitimate software paths to ensure it is not a false positive, especially if the executable is not listed in the exclusion paths.
* Analyze recent system logs and security events around the time of the alert to identify any other anomalous activities or patterns that could be related to the potential exploitation attempt.
* If the process is confirmed suspicious, isolate the affected system to prevent further exploitation and conduct a deeper forensic analysis to understand the scope and impact of the incident.

**False positive analysis**

* Legitimate print-related processes like splwow64.exe, PDFCreator.exe, and acrodist.exe may trigger alerts. These are excluded in the rule to prevent false positives.
* System processes such as msiexec.exe, route.exe, and WerFault.exe are known to be legitimate child processes of the Print Spooler and are excluded to reduce false alerts.
* Commands involving net.exe for starting or stopping services are common in administrative tasks and are excluded to avoid unnecessary alerts.
* Command-line operations involving cmd.exe or powershell.exe that reference .spl files or system paths are often legitimate and are excluded to minimize false positives.
* Network configuration changes using netsh.exe, such as adding port openings or rules, are typical in network management and are excluded to prevent false alerts.
* Registration of PrintConfig.dll via regsvr32.exe is a known legitimate operation and is excluded to avoid false positives.
* Executables from known paths like CutePDF Writer and GPLGS are excluded to prevent alerts from common, non-threatening applications.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further exploitation or lateral movement by the adversary.
* Terminate any suspicious child processes spawned by the Print Spooler service that do not match known legitimate processes or command lines.
* Conduct a thorough review of the system’s security logs to identify any unauthorized access or privilege escalation attempts related to the Print Spooler service.
* Apply the latest security patches and updates to the Windows operating system and specifically to the Print Spooler service to mitigate known vulnerabilities.
* Restore the system from a clean backup if any unauthorized changes or malicious activities are confirmed.
* Monitor the system closely for any recurrence of similar suspicious activities, ensuring enhanced logging and alerting are in place for spoolsv.exe and its child processes.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the potential impact on other systems within the network.


## Setup [_setup_719]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_1185]

```js
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "spoolsv.exe" and process.command_line != null and
 (?process.Ext.token.integrity_level_name : "System" or ?winlog.event_data.IntegrityLevel : "System") and

 /* exclusions for FP control below */
 not process.name : ("splwow64.exe", "PDFCreator.exe", "acrodist.exe", "spoolsv.exe", "msiexec.exe", "route.exe", "WerFault.exe") and
 not process.command_line : "*\\WINDOWS\\system32\\spool\\DRIVERS*" and
 not (process.name : "net.exe" and process.command_line : ("*stop*", "*start*")) and
 not (process.name : ("cmd.exe", "powershell.exe") and process.command_line : ("*.spl*", "*\\program files*", "*route add*")) and
 not (process.name : "netsh.exe" and process.command_line : ("*add portopening*", "*rule name*")) and
 not (process.name : "regsvr32.exe" and process.command_line : "*PrintConfig.dll*") and
 not process.executable : (
    "?:\\Program Files (x86)\\CutePDF Writer\\CPWriter2.exe",
    "?:\\Program Files (x86)\\GPLGS\\gswin32c.exe"
 )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



