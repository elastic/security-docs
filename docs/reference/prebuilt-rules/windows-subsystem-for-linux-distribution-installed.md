---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/windows-subsystem-for-linux-distribution-installed.html
---

# Windows Subsystem for Linux Distribution Installed [windows-subsystem-for-linux-distribution-installed]

Detects changes to the registry that indicates the install of a new Windows Subsystem for Linux distribution by name. Adversaries may enable and use WSL for Linux to avoid detection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.registry-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://learn.microsoft.com/en-us/windows/wsl/wsl-config](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 209

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1208]

**Triage and analysis**

**Investigating Windows Subsystem for Linux Distribution Installed**

The Windows Subsystem for Linux (WSL) lets developers install a Linux distribution (such as Ubuntu, OpenSUSE, Kali, Debian, Arch Linux, etc) and use Linux applications, utilities, and Bash command-line tools directly on Windows, unmodified, without the overhead of a traditional virtual machine or dualboot setup. Attackers may abuse WSL to avoid security protections on a Windows host and perform a wide range of attacks.

This rule identifies the installation of a new Windows Subsystem for Linux distribution via registry events.

**Possible investigation steps**

* Identify the user account that performed the action and whether it should perform this kind of action.
* Examine which distribution was installed. Some distributions such as Kali Linux can facilitate the compromise of the environment.
* Contact the account owner and confirm whether they are aware of this activity.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Validate that the activity is not related to planned patches, updates, network administrator activity, or legitimate software installations.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.

**False positive analysis**

* This is a dual-use tool, meaning its usage is not inherently malicious. Analysts can dismiss the alert if the administrator is aware of the activity, no other suspicious activity was identified, and the WSL distribution is homologated and approved in the environment.

**Related Rules**

* Host Files System Changes via Windows Subsystem for Linux - e88d1fe9-b2f4-48d4-bace-a026dc745d4b
* Execution via Windows Subsystem for Linux - db7dbad5-08d2-4d25-b9b1-d3a1e4a15efd
* Suspicious Execution via Windows Subsystem for Linux - 3e0eeb75-16e8-4f2f-9826-62461ca128b7
* Windows Subsystem for Linux Enabled via Dism Utility - e2e0537d-7d8f-4910-a11d-559bcf61295a

**Response and Remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_1236]

```js
registry where host.os.type == "windows" and event.type == "change" and registry.value : "PackageFamilyName" and
 registry.path : "*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Lxss\\*\\PackageFamilyName"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)

* Technique:

    * Name: Indirect Command Execution
    * ID: T1202
    * Reference URL: [https://attack.mitre.org/techniques/T1202/](https://attack.mitre.org/techniques/T1202/)



