---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/port-forwarding-rule-addition.html
---

# Port Forwarding Rule Addition [port-forwarding-rule-addition]

Identifies the creation of a new port forwarding rule. An adversary may abuse this technique to bypass network segmentation restrictions.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.registry-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-sentinel_one_cloud_funnel.*
* logs-m365_defender.event-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html](https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Command and Control
* Tactic: Defense Evasion
* Resources: Investigation Guide
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Microsoft Defender for Endpoint

**Version**: 413

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_639]

**Triage and analysis**

**Investigating Port Forwarding Rule Addition**

Network port forwarding is a mechanism to redirect incoming TCP connections (IPv4 or IPv6) from the local TCP port to any other port number, or even to a port on a remote computer.

Attackers may configure port forwarding rules to bypass network segmentation restrictions, using the host as a jump box to access previously unreachable systems.

This rule monitors the modifications to the `HKLM\SYSTEM\*ControlSet*\Services\PortProxy\v4tov4\` subkeys.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Contact the account and system owners and confirm whether they are aware of this activity.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.
* Identify the target host IP address, check the connections originating from the host where the modification occurred, and inspect the credentials used.
* Investigate suspicious login activity, such as unauthorized access and logins from outside working hours and unusual locations.

**False positive analysis**

* This mechanism can be used legitimately. Analysts can dismiss the alert if the Administrator is aware of the activity and there are justifications for this configuration.
* If this rule is noisy in your environment due to expected activity, consider adding exceptions — preferably with a combination of user and command line conditions.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Delete the port forwarding rule.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_681]

```js
registry where host.os.type == "windows" and registry.path : (
  "HKLM\\SYSTEM\\*ControlSet*\\Services\\PortProxy\\v4tov4\\*",
  "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\PortProxy\\v4tov4\\*",
  "MACHINE\\SYSTEM\\*ControlSet*\\Services\\PortProxy\\v4tov4\\*"
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Protocol Tunneling
    * ID: T1572
    * Reference URL: [https://attack.mitre.org/techniques/T1572/](https://attack.mitre.org/techniques/T1572/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



