---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-installation-of-security-support-provider.html
---

# Installation of Security Support Provider [prebuilt-rule-8-17-4-installation-of-security-support-provider]

Identifies registry modifications related to the Windows Security Support Provider (SSP) configuration. Adversaries may abuse this to establish persistence in an environment.

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

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 310

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4946]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Installation of Security Support Provider**

Security Support Providers (SSPs) in Windows environments facilitate authentication processes. Adversaries may exploit SSPs by modifying registry entries to maintain persistence or evade defenses. The detection rule identifies suspicious changes to specific registry paths associated with SSPs, excluding legitimate processes like msiexec.exe, to flag potential unauthorized modifications indicative of malicious activity.

**Possible investigation steps**

* Review the registry change event details to identify the specific registry path that was modified, focusing on paths related to "HKLM\SYSTEM*ControlSet*\Control\Lsa\Security Packages" and "HKLM\SYSTEM*ControlSet*\Control\Lsa\OSConfig\Security Packages".
* Investigate the process responsible for the registry modification by examining the process executable path, ensuring it is not a legitimate process like "C:\Windows\System32\msiexec.exe" or "C:\Windows\SysWOW64\msiexec.exe".
* Check the historical activity of the identified process to determine if it has been involved in other suspicious activities or registry changes.
* Analyze the user account context under which the process was executed to assess if it aligns with expected behavior or if it indicates potential compromise.
* Correlate the event with other security alerts or logs from data sources such as Elastic Endgame, Elastic Defend, Sysmon, Microsoft Defender for Endpoint, or SentinelOne to gather additional context and identify any related malicious activity.
* Evaluate the potential impact of the registry change on system security and persistence mechanisms, considering the MITRE ATT&CK tactic of Persistence and technique T1547.

**False positive analysis**

* Legitimate software installations or updates may trigger registry changes in SSP paths. Users can create exceptions for known software installers or updaters that frequently modify these registry entries.
* System administrators performing routine maintenance or configuration changes might inadvertently cause registry modifications. Document and exclude these activities when they are verified as non-threatening.
* Security software updates, including those from Microsoft or third-party vendors, may alter SSP configurations as part of their normal operation. Monitor and whitelist these updates to prevent false alerts.
* Automated deployment tools or scripts that modify system settings could lead to false positives. Ensure these tools are accounted for and excluded if they are part of regular operations.
* Custom scripts or applications developed in-house that interact with SSP registry paths should be reviewed and excluded if they are deemed safe and necessary for business operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes that are not whitelisted, especially those modifying the registry paths associated with Security Support Providers.
* Restore the modified registry entries to their original state using a known good backup or by manually correcting the entries to remove unauthorized changes.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious software or artifacts.
* Review and update access controls and permissions to ensure that only authorized personnel can modify critical registry paths related to Security Support Providers.
* Monitor the affected system and network for any signs of re-infection or further suspicious activity, focusing on registry changes and process executions.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.


## Rule query [_rule_query_5901]

```js
registry where host.os.type == "windows" and event.type == "change" and
   registry.path : (
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Security Packages*",
      "HKLM\\SYSTEM\\*ControlSet*\\Control\\Lsa\\OSConfig\\Security Packages*",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Security Packages*",
      "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Control\\Lsa\\OSConfig\\Security Packages*",
      "MACHINE\\SYSTEM\\*ControlSet*\\Control\\Lsa\\Security Packages*",
      "MACHINE\\SYSTEM\\*ControlSet*\\Control\\Lsa\\OSConfig\\Security Packages*"
   ) and
   not process.executable : ("C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\SysWOW64\\msiexec.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Security Support Provider
    * ID: T1547.005
    * Reference URL: [https://attack.mitre.org/techniques/T1547/005/](https://attack.mitre.org/techniques/T1547/005/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



