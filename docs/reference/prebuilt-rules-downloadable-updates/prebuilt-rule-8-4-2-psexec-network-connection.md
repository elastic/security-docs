---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-psexec-network-connection.html
---

# PsExec Network Connection [prebuilt-rule-8-4-2-psexec-network-connection]

Identifies use of the SysInternals tool PsExec.exe making a network connection. This could be an indication of lateral movement.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution
* Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3469]

## Triage and analysis

## Investigating PsExec Network Connection

PsExec is a remote administration tool that enables the execution of commands with both regular and SYSTEM privileges on Windows systems. Microsoft develops it as part of the Sysinternals Suite. Although commonly used by administrators, PsExec is frequently used by attackers to enable lateral movement and execute commands as SYSTEM to disable defenses and bypass security protections.

This rule identifies PsExec execution by looking for the creation of `PsExec.exe`, the default name for the utility, followed by a network connection done by the process.

### Possible investigation steps

- Check if the usage of this tool complies with the organization's administration policy.
- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Identify the target computer and its role in the IT environment.
- Investigate what commands were run, and assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.

## False positive analysis

- This mechanism can be used legitimately. As long as the analyst did not identify suspicious activity related to the user or involved hosts, and the tool is allowed by the organization's policy, such alerts can be dismissed.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
  - Prioritize accordingly with the role of the servers and users involved.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Review the privileges assigned to the user to ensure that the least privilege principle is being followed.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4132]

```js
sequence by process.entity_id
  [process where process.name : "PsExec.exe" and event.type == "start" and

   /* This flag suppresses the display of the license dialog and may
      indicate that psexec executed for the first time in the machine */
   process.args : "-accepteula" and

   not process.executable : ("?:\\ProgramData\\Docusnap\\Discovery\\discovery\\plugins\\17\\Bin\\psexec.exe",
                             "?:\\Docusnap 11\\Bin\\psexec.exe",
                             "?:\\Program Files\\Docusnap X\\Bin\\psexec.exe",
                             "?:\\Program Files\\Docusnap X\\Tools\\dsDNS.exe") and
   not process.parent.executable : "?:\\Program Files (x86)\\Cynet\\Cynet Scanner\\CynetScanner.exe"]
  [network where process.name : "PsExec.exe"]
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

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)



