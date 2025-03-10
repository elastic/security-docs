---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-msiexec-service-child-process-with-network-connection.html
---

# MsiExec Service Child Process With Network Connection [prebuilt-rule-8-17-4-msiexec-service-child-process-with-network-connection]

Identifies the execution of an MsiExec service child process followed by network or dns lookup activity. Adversaries may abuse Windows Installers for initial access and delivery of malware.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-endpoint.events.network-*
* logs-windows.sysmon_operational-*
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
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 202

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4782]

**Triage and analysis**

[TBC: QUOTE]
**Investigating MsiExec Service Child Process With Network Connection**

MsiExec is a Windows utility for installing, maintaining, and removing software. Adversaries exploit it to execute malicious payloads by disguising them as legitimate installations. The detection rule identifies suspicious child processes spawned by MsiExec that initiate network activity, which is atypical for standard installations. By focusing on unusual executable paths and network connections, the rule helps uncover potential misuse indicative of malware delivery or initial access attempts.

**Possible investigation steps**

* Review the process tree to identify the parent and child processes of the suspicious MsiExec activity, focusing on the process.entity_id and process.parent.name fields to understand the execution flow.
* Examine the process.executable path to determine if it deviates from typical installation paths, as specified in the query, to assess the likelihood of malicious activity.
* Analyze the network or DNS activity associated with the process by reviewing the event.category field for network or dns events, and correlate these with the process.name to identify any unusual or unauthorized connections.
* Check the process.args for any unusual or suspicious command-line arguments that might indicate an attempt to execute malicious payloads or scripts.
* Investigate the host’s recent activity and security logs to identify any other indicators of compromise or related suspicious behavior, leveraging data sources like Elastic Defend, Sysmon, or SentinelOne as mentioned in the rule’s tags.
* Assess the risk and impact of the detected activity by considering the context of the alert, such as the host’s role in the network and any potential data exposure or system compromise.

**False positive analysis**

* Legitimate software installations or updates may trigger the rule if they involve network activity. Users can create exceptions for known software update processes that are verified as safe.
* Custom enterprise applications that use MsiExec for deployment and require network access might be flagged. Identify these applications and exclude their specific executable paths from the rule.
* Automated deployment tools that utilize MsiExec and perform network operations could be misidentified. Review these tools and whitelist their processes to prevent false alerts.
* Security software or system management tools that leverage MsiExec for legitimate purposes may cause false positives. Confirm these tools' activities and add them to an exclusion list if necessary.
* Regularly review and update the exclusion list to ensure it reflects the current environment and any new legitimate software that may interact with MsiExec.

**Response and remediation**

* Isolate the affected system from the network immediately to prevent further malicious activity and lateral movement.
* Terminate the suspicious child process spawned by MsiExec to halt any ongoing malicious operations.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious payloads or remnants.
* Review and analyze the process execution and network activity logs to identify any additional indicators of compromise (IOCs) and assess the scope of the intrusion.
* Reset credentials and review access permissions for any accounts that may have been compromised or used during the attack.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and detection rules to identify similar threats in the future, focusing on unusual MsiExec activity and network connections.


## Rule query [_rule_query_5737]

```js
sequence by process.entity_id with maxspan=1m
 [process where host.os.type == "windows" and event.type : "start" and
  process.parent.name : "msiexec.exe" and process.parent.args : "/v" and
  not process.executable :
        ("?:\\Windows\\System32\\msiexec.exe",
         "?:\\Windows\\sysWOW64\\msiexec.exe",
         "?:\\Windows\\system32\\srtasks.exe",
         "?:\\Windows\\syswow64\\srtasks.exe",
         "?:\\Windows\\sys*\\taskkill.exe",
         "?:\\Program Files\\*.exe",
         "?:\\Program Files (x86)\\*.exe",
         "?:\\Windows\\Installer\\MSI*.tmp",
         "?:\\Windows\\Microsoft.NET\\Framework*\\RegSvcs.exe") and
 not (process.name : ("rundll32.exe", "regsvr32.exe") and process.args : ("?:\\Program Files\\*", "?:\\Program Files (x86)\\*"))]
[any where host.os.type == "windows" and event.category in ("network", "dns") and process.name != null]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Msiexec
    * ID: T1218.007
    * Reference URL: [https://attack.mitre.org/techniques/T1218/007/](https://attack.mitre.org/techniques/T1218/007/)



