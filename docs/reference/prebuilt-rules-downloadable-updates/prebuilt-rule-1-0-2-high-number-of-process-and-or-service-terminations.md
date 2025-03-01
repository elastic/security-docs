---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-high-number-of-process-and-or-service-terminations.html
---

# High Number of Process and/or Service Terminations [prebuilt-rule-1-0-2-high-number-of-process-and-or-service-terminations]

This rule identifies a high number (10) of process terminations (stop, delete, or suspend) from the same host within a short time period.

**Rule type**: threshold

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
* Impact

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1607]

## Triage and analysis

## Investigating High Number of Process and/or Service Terminations

Attackers can stop services and kill processes for a variety of purposes. For example, they can stop services associated
with business applications and databases to release the lock on files used by these applications so they may be encrypted,
or stop security and backup solutions, etc.

This rule identifies a high number (10) of service and/or process terminations (stop, delete, or suspend) from the same
host within a short time period.

### Possible investigation steps

- Investigate the script execution chain (parent process tree).
- Identify the user account that performed the action and whether it should perform this kind of action.
- Confirm whether the account owner is aware of the operation, and why it was performed.
- Investigate other alerts related to the user/host in the last 48 hours.
- Check for similar behavior in other hosts on the environment.
- Check if any files on the host machine have been encrypted.

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further destructive behavior, which is commonly associated with this activity.
- Reset the password of the involved accounts.
- Reimage the host operating system or restore it to the operational state.
- If any other destructive action was identified on the host, it is recommended to prioritize the investigation and look
for ransomware preparation and execution activities.

## Rule query [_rule_query_1856]

```js
event.category:process and event.type:start and process.name:(net.exe or sc.exe or taskkill.exe) and
 process.args:(stop or pause or delete or "/PID" or "/IM" or "/T" or "/F" or "/t" or "/f" or "/im" or "/pid")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Service Stop
    * ID: T1489
    * Reference URL: [https://attack.mitre.org/techniques/T1489/](https://attack.mitre.org/techniques/T1489/)



