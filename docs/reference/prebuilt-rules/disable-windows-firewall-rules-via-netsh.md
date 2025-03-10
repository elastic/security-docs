---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/disable-windows-firewall-rules-via-netsh.html
---

# Disable Windows Firewall Rules via Netsh [disable-windows-firewall-rules-via-netsh]

Identifies use of the netsh.exe to disable or weaken the local firewall. Attackers will use this command line tool to disable the firewall during troubleshooting or to enable network mobility.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-crowdstrike.fdr*

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
* Tactic: Defense Evasion
* Resources: Investigation Guide
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike

**Version**: 312

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_270]

**Triage and analysis**

**Investigating Disable Windows Firewall Rules via Netsh**

The Windows Defender Firewall is a native component which provides host-based, two-way network traffic filtering for a device, and blocks unauthorized network traffic flowing into or out of the local device.

Attackers can disable the Windows firewall or its rules to enable lateral movement and command and control activity.

This rule identifies patterns related to disabling the Windows firewall or its rules using the `netsh.exe` utility.

**Possible investigation steps**

* Identify the user account that performed the action and whether it should perform this kind of action.
* Contact the user to check if they are aware of the operation.
* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate other alerts associated with the user/host during the past 48 hours.

**False positive analysis**

* This mechanism can be used legitimately. Check whether the user is an administrator and is legitimately performing troubleshooting.
* In case of an allowed benign true positive (B-TP), assess adding rules to allow needed traffic and re-enable the firewall.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Review the privileges assigned to the involved users to ensure that the least privilege principle is being followed.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_280]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.name : "netsh.exe" and
  (
    (process.args : "disable" and process.args : "firewall" and process.args : "set") or
    (process.args : "advfirewall" and process.args : "off" and process.args : "state")
  )
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



