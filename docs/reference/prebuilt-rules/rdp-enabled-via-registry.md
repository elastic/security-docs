---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/rdp-enabled-via-registry.html
---

# RDP Enabled via Registry [rdp-enabled-via-registry]

Identifies registry write modifications to enable Remote Desktop Protocol (RDP) access. This could be indicative of adversary lateral movement preparation.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

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
* Tactic: Lateral Movement
* Tactic: Defense Evasion
* Resources: Investigation Guide
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne

**Version**: 312

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_848]

**Triage and analysis**

**Investigating RDP Enabled via Registry**

Microsoft Remote Desktop Protocol (RDP) is a proprietary Microsoft protocol that enables remote connections to other computers, typically over TCP port 3389.

Attackers can use RDP to conduct their actions interactively. Ransomware operators frequently use RDP to access victim servers, often using privileged accounts.

This rule detects modification of the fDenyTSConnections registry key to the value `0`, which specifies that remote desktop connections are enabled. Attackers can abuse remote registry, use psexec, etc., to enable RDP and move laterally.

**Possible investigation steps**

* Identify the user account that performed the action and whether it should perform this kind of action.
* Contact the user to check if they are aware of the operation.
* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Check whether it makes sense to enable RDP to this host, given its role in the environment.
* Check if the host is directly exposed to the internet.
* Check whether privileged accounts accessed the host shortly after the modification.
* Review network events within a short timespan of this alert for incoming RDP connection attempts.

**False positive analysis**

* This mechanism can be used legitimately. Check whether the user should be performing this kind of activity, whether they are aware of it, whether RDP should be open, and whether the action exposes the environment to unnecessary risks.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* If RDP is needed, make sure to secure it using firewall rules:
* Allowlist RDP traffic to specific trusted hosts.
* Restrict RDP logins to authorized non-administrator accounts, where possible.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Review the privileges assigned to the involved users to ensure that the least privilege principle is being followed.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_906]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
    "HKLM\\SYSTEM\\*ControlSet*\\Control\\Terminal Server\\fDenyTSConnections",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Terminal Server\\fDenyTSConnections",
    "MACHINE\\*ControlSet*\\Control\\Terminal Server\\fDenyTSConnections"
  ) and
  registry.data.strings : ("0", "0x00000000") and
  not process.executable : ("?:\\Windows\\System32\\SystemPropertiesRemote.exe",
                            "?:\\Windows\\System32\\SystemPropertiesComputerName.exe",
                            "?:\\Windows\\System32\\SystemPropertiesAdvanced.exe",
                            "?:\\Windows\\System32\\SystemSettingsAdminFlows.exe",
                            "?:\\Windows\\WinSxS\\*\\TiWorker.exe",
                            "?:\\Windows\\system32\\svchost.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: Remote Desktop Protocol
    * ID: T1021.001
    * Reference URL: [https://attack.mitre.org/techniques/T1021/001/](https://attack.mitre.org/techniques/T1021/001/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



