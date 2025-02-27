---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-disable-windows-firewall-rules-via-netsh.html
---

# Disable Windows Firewall Rules via Netsh [prebuilt-rule-1-0-2-disable-windows-firewall-rules-via-netsh]

Identifies use of netsh.exe to disable or weaken the local firewall. Attackers will use this command line tool to disable the firewall during troubleshooting or to enable network mobility.

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
* Defense Evasion

**Version**: 11

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1535]

## Triage and analysis

## Investigating Disable Windows Firewall Rules via Netsh

The Windows Defender Firewall is a native component which provides host-based, two-way network traffic filtering for a
device, and blocks unauthorized network traffic flowing into or out of the local device.

Attackers can disable firewall rules which are intended to prevent lateral movement and command and control traffic to
enable their operations.

This rule identifies patterns related to disabling firewall rules using the `netsh.exe` utility.

### Possible investigation steps

- Identify the user account which performed the action and whether it should perform this kind of action.
- Contact the user to check if they are aware of the operation.
- Investigate the script execution chain (parent process tree).
- Investigate other alerts related to the user/host in the last 48 hours.
- Analyze the executed command to determine what it allowed.

## False positive analysis

- This mechanism can be used legitimately. Check whether the user is legitimately performing this kind of activity.
- Assess the need to disable the modification of the rule, and whether these actions expose the environment to
unnecessary risks.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Quarantine the involved host to prevent further post-compromise behavior.
- Evaluate exceptions that can be added to the firewall rule and re-enable the rule.
- Review the implicated account's privileges.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1773]

```js
process where event.type in ("start", "process_started") and
  process.name : "netsh.exe" and
  (process.args : "disable" and process.args : "firewall" and process.args : "set") or
  (process.args : "advfirewall" and process.args : "off" and process.args : "state")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify System Firewall
    * ID: T1562.004
    * Reference URL: [https://attack.mitre.org/techniques/T1562/004/](https://attack.mitre.org/techniques/T1562/004/)



