---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-whoami-process-activity.html
---

# Whoami Process Activity [prebuilt-rule-8-4-2-whoami-process-activity]

Identifies suspicious use of whoami.exe which displays user, group, and privileges information for the user who is currently logged on to the local system.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* logs-system.*
* endgame-*

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
* Discovery
* Investigation Guide
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3456]

## Triage and analysis

## Investigating Whoami Process Activity

After successfully compromising an environment, attackers may try to gain situational awareness to plan their next steps. This can happen by running commands to enumerate network resources, users, connections, files, and installed security software.

This rule looks for the execution of the `whoami` utility. Attackers commonly use this utility to measure their current privileges, discover the current user, determine if a privilege escalation was successful, etc.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Investigate any abnormal account behavior, such as command executions, file creations or modifications, and network connections.

## False positive analysis

- Discovery activities are not inherently malicious if they occur in isolation. As long as the analyst did not identify suspicious activity related to the user or host, such alerts can be dismissed.

## Related rules

- Account Discovery Command via SYSTEM Account - 2856446a-34e6-435b-9fb5-f8f040bfa7ed

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_4117]

```js
process where event.type == "start" and process.name : "whoami.exe" and
(

 (/* scoped for whoami execution under system privileges */
  (user.domain : ("NT AUTHORITY", "NT-AUTORITÄT", "AUTORITE NT", "IIS APPPOOL") or user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20")) and

   not (process.parent.name : "cmd.exe" and
        process.parent.args : ("chcp 437>nul 2>&1 & C:\\WINDOWS\\System32\\whoami.exe  /groups",
                               "chcp 437>nul 2>&1 & %systemroot%\\system32\\whoami /user",
                               "C:\\WINDOWS\\System32\\whoami.exe /groups",
                               "*WINDOWS\\system32\\config\\systemprofile*")) and
   not (process.parent.executable : "C:\\Windows\\system32\\inetsrv\\appcmd.exe" and process.parent.args : "LIST") and
   not process.parent.executable : ("C:\\Program Files\\Microsoft Monitoring Agent\\Agent\\MonitoringHost.exe",
                                    "C:\\Program Files\\Cohesity\\cohesity_windows_agent_service.exe")) or

  process.parent.name : ("wsmprovhost.exe", "w3wp.exe", "wmiprvse.exe", "rundll32.exe", "regsvr32.exe")

)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Owner/User Discovery
    * ID: T1033
    * Reference URL: [https://attack.mitre.org/techniques/T1033/](https://attack.mitre.org/techniques/T1033/)



