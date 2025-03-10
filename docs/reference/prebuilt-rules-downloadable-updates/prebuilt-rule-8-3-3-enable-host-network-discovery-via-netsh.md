---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-enable-host-network-discovery-via-netsh.html
---

# Enable Host Network Discovery via Netsh [prebuilt-rule-8-3-3-enable-host-network-discovery-via-netsh]

Identifies use of the netsh.exe program to enable host discovery via the network. Attackers can use this command-line tool to weaken the host firewall settings.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

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
* Investigation Guide
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3055]

## Triage and analysis

## Investigating Enable Host Network Discovery via Netsh

The Windows Defender Firewall is a native component that provides host-based, two-way network traffic filtering for a device and blocks unauthorized network traffic flowing into or out of the local device.

Attackers can enable Network Discovery on the Windows firewall to find other systems present in the same network. Systems with this setting enabled will communicate with other systems using broadcast messages, which can be used to identify targets for lateral movement. This rule looks for the setup of this setting using the netsh utility.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Inspect the host for suspicious or abnormal behavior in the alert timeframe.

## False positive analysis

- This mechanism can be used legitimately. Analysts can dismiss the alert if the Administrator is aware of the activity and there are justifications for this configuration.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved hosts to prevent further post-compromise behavior.
- Disable Network Discovery:
    - Using netsh: `netsh advfirewall firewall set rule group="Network Discovery" new enable=No`
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Review the privileges assigned to the involved users to ensure that the least privilege principle is being followed.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_3553]

```js
process where event.type == "start" and
process.name : "netsh.exe" and
process.args : ("firewall", "advfirewall") and process.args : "group=Network Discovery" and process.args : "enable=Yes"
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



