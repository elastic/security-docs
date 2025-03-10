---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/solarwinds-process-disabling-services-via-registry.html
---

# SolarWinds Process Disabling Services via Registry [solarwinds-process-disabling-services-via-registry]

Identifies a SolarWinds binary modifying the start type of a service to be disabled. An adversary may abuse this technique to manipulate relevant security services.

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

* [https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Initial Access
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 312

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_934]

**Triage and analysis**

[TBC: QUOTE]
**Investigating SolarWinds Process Disabling Services via Registry**

SolarWinds software is integral for network management, often requiring deep system access. Adversaries may exploit this by altering registry settings to disable critical services, evading detection. The detection rule identifies changes to service start types by specific SolarWinds processes, flagging potential misuse aimed at disabling security defenses. This proactive monitoring helps mitigate risks associated with unauthorized registry modifications.

**Possible investigation steps**

* Review the process name involved in the alert to confirm it matches one of the specified SolarWinds processes, such as "SolarWinds.BusinessLayerHost*.exe" or "NetFlowService*.exe".
* Examine the registry path in the alert to ensure it corresponds to the critical service start type locations, such as "HKLM\\SYSTEM\*ControlSet*\\Services\\*\\Start".
* Check the registry data value to verify if it has been set to "4" (disabled), indicating a potential attempt to disable a service.
* Investigate the timeline of the registry change event to identify any preceding or subsequent suspicious activities on the host.
* Correlate the alert with other security logs or alerts from data sources like Sysmon or Microsoft Defender for Endpoint to identify any related malicious activities or patterns.
* Assess the impacted service to determine its role in security operations and evaluate the potential impact of it being disabled.
* Contact the system owner or administrator to verify if the registry change was authorized or part of a legitimate maintenance activity.

**False positive analysis**

* Routine updates or maintenance by SolarWinds software may trigger registry changes. Verify if the process corresponds to a scheduled update or maintenance task and consider excluding these specific processes during known maintenance windows.
* Legitimate configuration changes by IT administrators using SolarWinds tools can appear as registry modifications. Confirm with the IT team if the changes align with authorized configuration activities and create exceptions for these known activities.
* Automated scripts or tools that utilize SolarWinds processes for legitimate network management tasks might cause false positives. Review the scripts or tools in use and whitelist them if they are verified as safe and necessary for operations.
* Temporary service modifications for troubleshooting purposes by SolarWinds processes can be mistaken for malicious activity. Ensure that any troubleshooting activities are documented and create temporary exceptions during these periods.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized registry modifications and potential lateral movement by the adversary.
* Terminate any suspicious SolarWinds processes identified in the alert, such as "SolarWinds.BusinessLayerHost*.exe" or "NetFlowService*.exe", to halt any ongoing malicious activity.
* Restore the registry settings for the affected services to their original state, ensuring that critical security services are re-enabled and configured to start automatically.
* Conduct a thorough review of the affected system for additional signs of compromise, including unauthorized user accounts, scheduled tasks, or other persistence mechanisms.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the scope of the breach.
* Implement enhanced monitoring on the affected system and similar environments to detect any future unauthorized registry changes, leveraging data sources like Sysmon and Microsoft Defender for Endpoint.
* Review and update access controls and permissions for SolarWinds processes to limit their ability to modify critical system settings, reducing the risk of future exploitation.


## Rule query [_rule_query_995]

```js
registry where host.os.type == "windows" and event.type == "change" and registry.value : "Start" and
  process.name : (
      "SolarWinds.BusinessLayerHost*.exe",
      "ConfigurationWizard*.exe",
      "NetflowDatabaseMaintenance*.exe",
      "NetFlowService*.exe",
      "SolarWinds.Administration*.exe",
      "SolarWinds.Collector.Service*.exe",
      "SolarwindsDiagnostics*.exe"
  ) and
  registry.path : (
    "HKLM\\SYSTEM\\*ControlSet*\\Services\\*\\Start",
    "\\REGISTRY\\MACHINE\\SYSTEM\\*ControlSet*\\Services\\*\\Start",
    "MACHINE\\SYSTEM\\*ControlSet*\\Services\\*\\Start"
  ) and
  registry.data.strings : ("4", "0x00000004")
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

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Supply Chain Compromise
    * ID: T1195
    * Reference URL: [https://attack.mitre.org/techniques/T1195/](https://attack.mitre.org/techniques/T1195/)

* Sub-technique:

    * Name: Compromise Software Supply Chain
    * ID: T1195.002
    * Reference URL: [https://attack.mitre.org/techniques/T1195/002/](https://attack.mitre.org/techniques/T1195/002/)



