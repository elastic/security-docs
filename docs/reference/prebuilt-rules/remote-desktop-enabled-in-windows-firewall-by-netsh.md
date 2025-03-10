---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/remote-desktop-enabled-in-windows-firewall-by-netsh.html
---

# Remote Desktop Enabled in Windows Firewall by Netsh [remote-desktop-enabled-in-windows-firewall-by-netsh]

Identifies use of the network shell utility (netsh.exe) to enable inbound Remote Desktop Protocol (RDP) connections in the Windows Firewall.

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

## Investigation guide [_investigation_guide_865]

**Triage and analysis**

**Investigating Remote Desktop Enabled in Windows Firewall by Netsh**

Microsoft Remote Desktop Protocol (RDP) is a proprietary Microsoft protocol that enables remote connections to other computers, typically over TCP port 3389.

Attackers can use RDP to conduct their actions interactively. Ransomware operators frequently use RDP to access victim servers, often using privileged accounts.

This rule detects the creation of a Windows Firewall inbound rule that would allow inbound RDP traffic using the `netsh.exe` utility.

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

* The `netsh.exe` utility can be used legitimately. Check whether the user should be performing this kind of activity, whether the user is aware of it, whether RDP should be open, and whether the action exposes the environment to unnecessary risks.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* If RDP is needed, make sure to secure it:
* Allowlist RDP traffic to specific trusted hosts.
* Restrict RDP logins to authorized non-administrator accounts, where possible.
* Isolate the involved hosts to prevent further post-compromise behavior.
* Review the privileges assigned to the involved users to ensure that the least privilege principle is being followed.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_921]

```js
process where host.os.type == "windows" and event.type == "start" and
 (process.name : "netsh.exe" or ?process.pe.original_file_name == "netsh.exe") and
 process.args : ("localport=3389", "RemoteDesktop", "group=\"remote desktop\"") and
 process.args : ("action=allow", "enable=Yes", "enable")
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



