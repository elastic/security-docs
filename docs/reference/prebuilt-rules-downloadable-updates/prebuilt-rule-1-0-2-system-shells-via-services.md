---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-system-shells-via-services.html
---

# System Shells via Services [prebuilt-rule-1-0-2-system-shells-via-services]

Windows services typically run as SYSTEM and can be used as a privilege escalation opportunity. Malware or penetration testers may run a shell as a service to gain SYSTEM permissions.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
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

**Version**: 11

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1646]

## Triage and analysis

## Investigating System Shells via Services

Attackers may configure existing services or create new ones to execute system shells to elevate their privileges from
administrator to SYSTEM. They can also configure services to execute these shells with persistence payloads.

This rule looks for system shells being spawned by `services.exe`, which is compatible with the above behavior.

### Possible investigation steps

- Investigate the process execution chain (parent process tree).
- Identify how the service was created or modified. Look for registry changes events or Windows events related to
service activities (for example, 4697 and/or 7045).
  - Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Check for similar behavior in other hosts on the environment.
- Check for commands executed under the spawned shell.

## False positive analysis

- This activity should not happen legitimately. The security team should address any potential benign true positive
(B-TP), as this configuration can put the user and the domain at risk.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- Reset passwords for the user account and other potentially compromised accounts (email, services, CRMs, etc.).
- Delete the service or restore it to the original configuration.
- Investigate the initial attack vector.


## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1907]

```js
process where event.type in ("start", "process_started") and
  process.parent.name : "services.exe" and
  process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe") and

  /* Third party FP's */
  not process.args : "NVDisplay.ContainerLocalSystem"
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



