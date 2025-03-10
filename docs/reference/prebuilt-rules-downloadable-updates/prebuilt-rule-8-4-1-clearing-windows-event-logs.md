---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-clearing-windows-event-logs.html
---

# Clearing Windows Event Logs [prebuilt-rule-8-4-1-clearing-windows-event-logs]

Identifies attempts to clear or disable Windows event log stores using Windows wevetutil command. This is often done by attackers in an attempt to evade detection or destroy forensic evidence on a system.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
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
* Defense Evasion
* Investigation Guide
* Elastic Endgame

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2716]

## Triage and analysis

## Investigating Clearing Windows Event Logs

Windows event logs are a fundamental data source for security monitoring, forensics, and incident response. Adversaries
can tamper, clear, and delete this data to break SIEM detections, cover their tracks, and slow down incident response.

This rule looks for the execution of the `wevtutil.exe` utility or the `Clear-EventLog` cmdlet to clear event logs.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files
for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
  - Verify if any other anti-forensics behaviors were observed.
- Investigate the event logs prior to the action for suspicious behaviors that an attacker may be trying to cover up.

## False positive analysis

- This mechanism can be used legitimately. Analysts can dismiss the alert if the administrator is aware of the activity
and there are justifications for this action.
- Analyze whether the cleared event log is pertinent to security and general monitoring. Administrators can clear
non-relevant event logs using this mechanism. If this activity is expected and noisy in your environment, consider
adding exceptions — preferably with a combination of user and command line conditions.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
  - This activity is potentially done after the adversary achieves its objectives on the host. Ensure that previous
  actions, if any, are investigated accordingly with their response playbooks.
- Isolate the involved host to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_3108]

```js
process where event.type == "start" and
  (
    (process.name : "wevtutil.exe" or process.pe.original_file_name == "wevtutil.exe") and
    process.args : ("/e:false", "cl", "clear-log")
  ) or
  (
    process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and
    process.args : "Clear-EventLog"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Indicator Removal on Host
    * ID: T1070
    * Reference URL: [https://attack.mitre.org/techniques/T1070/](https://attack.mitre.org/techniques/T1070/)

* Sub-technique:

    * Name: Clear Windows Event Logs
    * ID: T1070.001
    * Reference URL: [https://attack.mitre.org/techniques/T1070/001/](https://attack.mitre.org/techniques/T1070/001/)



