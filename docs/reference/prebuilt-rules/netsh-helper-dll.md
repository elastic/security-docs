---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/netsh-helper-dll.html
---

# Netsh Helper DLL [netsh-helper-dll]

Identifies the addition of a Netsh Helper DLL, netsh.exe supports the addition of these DLLs to extend its functionality. Attackers may abuse this mechanism to execute malicious payloads every time the utility is executed, which can be done by administrators or a scheduled task.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-windows.sysmon_operational-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 203

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_571]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Netsh Helper DLL**

Netsh, a command-line utility in Windows, allows for network configuration and diagnostics. It supports extensibility through Helper DLLs, which can be added to enhance its capabilities. However, attackers can exploit this by adding malicious DLLs, ensuring their code runs whenever netsh is executed. The detection rule monitors registry changes related to netsh DLLs, flagging unauthorized modifications that may indicate persistence tactics.

**Possible investigation steps**

* Review the registry path specified in the alert to confirm the presence of any unauthorized or suspicious DLLs under "HKLM\Software\Microsoft\netsh\".
* Check the timestamp of the registry change event to determine when the modification occurred and correlate it with any other suspicious activities or events on the system.
* Investigate the origin of the DLL file by examining its properties, such as the file path, creation date, and digital signature, to assess its legitimacy.
* Analyze recent user activity and scheduled tasks to identify any potential execution of netsh.exe that could have triggered the malicious DLL.
* Cross-reference the alert with other security logs and alerts from data sources like Microsoft Defender for Endpoint or Sysmon to gather additional context and identify any related threats or indicators of compromise.

**False positive analysis**

* Legitimate software installations or updates may add or modify Netsh Helper DLLs, triggering the detection rule. Users should verify if recent installations or updates coincide with the registry changes.
* Network management tools or scripts used by IT departments might legitimately extend netsh functionality. Identify and document these tools to create exceptions in the detection rule.
* Scheduled tasks or administrative scripts that configure network settings could cause expected changes. Review scheduled tasks and scripts to ensure they are authorized and adjust the rule to exclude these known activities.
* Security software or network monitoring solutions may interact with netsh for legitimate purposes. Confirm with the software vendor if their product modifies netsh settings and consider excluding these changes from the rule.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further execution of the malicious DLL and potential lateral movement.
* Terminate any suspicious processes associated with netsh.exe to halt the execution of the malicious payload.
* Remove the unauthorized Netsh Helper DLL entry from the registry path identified in the alert to eliminate the persistence mechanism.
* Conduct a thorough scan of the affected system using an updated antivirus or endpoint detection and response (EDR) tool to identify and remove any additional malicious files or artifacts.
* Review and restore any altered system configurations to their original state to ensure system integrity.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for registry changes related to Netsh Helper DLLs to detect similar threats in the future.


## Rule query [_rule_query_612]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
    "HKLM\\Software\\Microsoft\\netsh\\*",
    "\\REGISTRY\\MACHINE\\Software\\Microsoft\\netsh\\*",
    "MACHINE\\Software\\Microsoft\\netsh\\*"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Netsh Helper DLL
    * ID: T1546.007
    * Reference URL: [https://attack.mitre.org/techniques/T1546/007/](https://attack.mitre.org/techniques/T1546/007/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



