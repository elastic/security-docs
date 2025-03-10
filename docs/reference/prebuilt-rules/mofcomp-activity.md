---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/mofcomp-activity.html
---

# Mofcomp Activity [mofcomp-activity]

Managed Object Format (MOF) files can be compiled locally or remotely through mofcomp.exe. Attackers may leverage MOF files to build their own namespaces and classes into the Windows Management Instrumentation (WMI) repository, or establish persistence using WMI Event Subscription.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-m365_defender.event-*
* endgame-*
* logs-system.security-*
* logs-crowdstrike.fdr*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: Elastic Defend
* Data Source: Microsoft Defender for Endpoint
* Data Source: Elastic Endgame
* Data Source: System
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_548]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Mofcomp Activity**

Mofcomp.exe is a tool used to compile Managed Object Format (MOF) files, which define classes and namespaces in the Windows Management Instrumentation (WMI) repository. Adversaries exploit this by creating malicious WMI scripts for persistence or execution. The detection rule identifies suspicious mofcomp.exe activity by filtering out legitimate processes and focusing on unusual executions, excluding known safe parent processes and system accounts.

**Possible investigation steps**

* Review the process execution details to confirm the presence of mofcomp.exe and verify the command-line arguments used, focusing on any unusual or unexpected MOF file paths.
* Investigate the user account associated with the process execution, especially if it is not the system account (S-1-5-18), to determine if the account has been compromised or is being misused.
* Examine the parent process of mofcomp.exe to ensure it is not a known safe process like ScenarioEngine.exe, and assess whether the parent process is legitimate or potentially malicious.
* Check for any recent changes or additions to the WMI repository, including new namespaces or classes, which could indicate malicious activity or persistence mechanisms.
* Correlate the alert with other security events or logs from data sources like Microsoft Defender for Endpoint or Crowdstrike to identify any related suspicious activities or patterns.

**False positive analysis**

* Legitimate SQL Server operations may trigger the rule when SQL Server components compile MOF files. To handle this, exclude processes with parent names like ScenarioEngine.exe and specific MOF file paths related to SQL Server.
* System maintenance tasks executed by trusted system accounts can cause false positives. Exclude activities initiated by the system account with user ID S-1-5-18 to reduce noise.
* Regular administrative tasks involving WMI may appear suspicious. Identify and document these tasks, then create exceptions for known safe parent processes or specific MOF file paths to prevent unnecessary alerts.
* Software installations or updates that involve MOF file compilation might be flagged. Monitor installation logs and exclude these processes if they are verified as part of legitimate software updates.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate the mofcomp.exe process if it is confirmed to be executing malicious MOF files.
* Conduct a thorough review of the WMI repository to identify and remove any unauthorized namespaces or classes that may have been created by the attacker.
* Remove any malicious MOF files from the system to prevent re-execution.
* Restore the system from a known good backup if unauthorized changes to the WMI repository or system files are detected.
* Monitor for any recurrence of similar activity by setting up alerts for unusual mofcomp.exe executions and unauthorized WMI modifications.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.


## Rule query [_rule_query_589]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.name : "mofcomp.exe" and process.args : "*.mof" and
  not user.id : "S-1-5-18" and
  not
  (
    process.parent.name : "ScenarioEngine.exe" and
    process.args : (
      "*\\MSSQL\\Binn\\*.mof",
      "*\\Microsoft SQL Server\\???\\Shared\\*.mof",
      "*\\OLAP\\bin\\*.mof"
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Windows Management Instrumentation
    * ID: T1047
    * Reference URL: [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Windows Management Instrumentation Event Subscription
    * ID: T1546.003
    * Reference URL: [https://attack.mitre.org/techniques/T1546/003/](https://attack.mitre.org/techniques/T1546/003/)



