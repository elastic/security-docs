---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-suspicious-service-was-installed-in-the-system.html
---

# Suspicious service was installed in the system [prebuilt-rule-8-3-3-suspicious-service-was-installed-in-the-system]

Identifies the creation of a new Windows service with suspicious Service command values. Windows services typically run as SYSTEM and can be used for privilege escalation and persistence.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2863]

## Triage and analysis

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify how the service was created or modified. Look for registry changes events or Windows events related to service activities (for example, 4697 and/or 7045).
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.


## False positive analysis

- Certain services such as PSEXECSVC may happen legitimately. The security team should address any potential benign true positive (B-TP) by excluding the relevant FP by pattern.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Delete the service or restore it to the original configuration.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_3275]

```js
any where
  (event.code : "4697" and
   (winlog.event_data.ServiceFileName : ("*COMSPEC*", "*\\172.0.0.1*", "*Admin$*", "*powershell*", "*rundll32*", "*cmd.exe*", "*PSEXESVC*", "*echo*", "*RemComSvc*") or
   winlog.event_data.ServiceFileName regex~ """%systemroot%\\[a-z0-9]+\.exe""")) or

  (event.code : "7045" and
   winlog.event_data.ImagePath : ("*COMSPEC*", "*\\172.0.0.1*", "*Admin$*", "*powershell*", "*rundll32*", "*cmd.exe*", "*PSEXESVC*", "*echo*", "*RemComSvc*"))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)



