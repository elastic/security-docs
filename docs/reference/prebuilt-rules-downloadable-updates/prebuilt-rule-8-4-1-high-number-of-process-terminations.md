---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-high-number-of-process-terminations.html
---

# High Number of Process Terminations [prebuilt-rule-8-4-1-high-number-of-process-terminations]

This rule identifies a high number (10) of process terminations via pkill from the same host within a short time period.

**Rule type**: threshold

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Impact
* Investigation Guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2658]

## Triage and analysis

## Investigating High Number of Process Terminations

Attackers can kill processes for a variety of purposes. For example, they can kill process associated
with business applications and databases to release the lock on files used by these applications so they may be
encrypted,or stop security and backup solutions, etc.

This rule identifies a high number (10) of process terminations via pkill from the same
host within a short time period.

### Possible investigation steps

Detection alerts from this rule indicate High Number of Process Terminations from the same host
Here are some possible avenues of investigation:
- Examine the entry point to the host and user in action via the Analyse View.
  - Identify the session entry leader and session user
- Examine the contents of session leading to the process termination(s) via the Session View.
  - Examine the command execution pattern in the session, which may lead to suspricous activities
- Examine the process killed during the malicious execution
  - Identify imment threat to the system from the process killed
  - Take necessary incident response actions to respawn necessary process

## False positive analysis

- This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further destructive behavior, which is commonly associated with this activity.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business
systems, and web services.
- Reimage the host operating system or restore it to the operational state.
- If any other destructive action was identified on the host, it is recommended to prioritize the investigation and look
for ransomware preparation and execution activities.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and
malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_3045]

```js
event.category:process and event.type:start and process.name:"pkill" and process.args:"-f"
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



