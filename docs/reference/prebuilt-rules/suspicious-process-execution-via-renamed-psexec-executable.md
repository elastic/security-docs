---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-process-execution-via-renamed-psexec-executable.html
---

# Suspicious Process Execution via Renamed PsExec Executable [suspicious-process-execution-via-renamed-psexec-executable]

Identifies suspicious psexec activity which is executing from the psexec service that has been renamed, possibly to evade detection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint

**Version**: 212

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1025]

**Triage and analysis**

**Investigating Suspicious Process Execution via Renamed PsExec Executable**

PsExec is a remote administration tool that enables the execution of commands with both regular and SYSTEM privileges on Windows systems. It operates by executing a service component `Psexecsvc` on a remote system, which then runs a specified process and returns the results to the local system. Microsoft develops PsExec as part of the Sysinternals Suite. Although commonly used by administrators, PsExec is frequently used by attackers to enable lateral movement and execute commands as SYSTEM to disable defenses and bypass security protections.

This rule identifies instances where the PsExec service component is executed using a custom name. This behavior can indicate an attempt to bypass security controls or detections that look for the default PsExec service component name.

**Possible investigation steps**

* Check if the usage of this tool complies with the organization’s administration policy.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Identify the target computer and its role in the IT environment.
* Investigate what commands were run, and assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.

**False positive analysis**

* This mechanism can be used legitimately. As long as the analyst did not identify suspicious activity related to the user or involved hosts, and the tool is allowed by the organization’s policy, such alerts can be dismissed.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Prioritize cases involving critical servers and users.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Review the privileges assigned to the user to ensure that the least privilege principle is being followed.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_1076]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.pe.original_file_name : "psexesvc.exe" and not process.name : "PSEXESVC.exe"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: System Services
    * ID: T1569
    * Reference URL: [https://attack.mitre.org/techniques/T1569/](https://attack.mitre.org/techniques/T1569/)

* Sub-technique:

    * Name: Service Execution
    * ID: T1569.002
    * Reference URL: [https://attack.mitre.org/techniques/T1569/002/](https://attack.mitre.org/techniques/T1569/002/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Rename System Utilities
    * ID: T1036.003
    * Reference URL: [https://attack.mitre.org/techniques/T1036/003/](https://attack.mitre.org/techniques/T1036/003/)



