---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/werfault-reflectdebugger-persistence.html
---

# Werfault ReflectDebugger Persistence [werfault-reflectdebugger-persistence]

Identifies the registration of a Werfault Debugger. Attackers may abuse this mechanism to execute malicious payloads every time the utility is executed with the "-pr" parameter.

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

**References**:

* [https://cocomelonc.github.io/malware/2022/11/02/malware-pers-18.html](https://cocomelonc.github.io/malware/2022/11/02/malware-pers-18.md)

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

## Investigation guide [_investigation_guide_1196]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Werfault ReflectDebugger Persistence**

Werfault, the Windows Error Reporting service, can be manipulated by attackers to maintain persistence. By registering a ReflectDebugger, adversaries can execute malicious code whenever Werfault is triggered with specific parameters. The detection rule monitors registry changes in key paths associated with ReflectDebugger, alerting on unauthorized modifications indicative of potential abuse.

**Possible investigation steps**

* Review the registry change event details to identify the specific path modified, focusing on the paths listed in the query: "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger", "\REGISTRY\MACHINE\Software\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger", or "MACHINE\Software\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger".
* Check the timestamp of the registry change event to determine when the modification occurred and correlate it with other suspicious activities or events on the system around the same time.
* Investigate the user account or process responsible for the registry change to assess whether it is a legitimate action or potentially malicious. Look for unusual or unauthorized accounts making the change.
* Examine the system for any recent executions of Werfault with the "-pr" parameter, as this could indicate attempts to trigger the malicious payload.
* Search for any related alerts or logs from data sources such as Elastic Endgame, Elastic Defend, Microsoft Defender for Endpoint, SentinelOne, or Sysmon that might provide additional context or corroborate the suspicious activity.
* Assess the system for any signs of compromise or persistence mechanisms, such as unexpected startup items, scheduled tasks, or other registry modifications that could indicate a broader attack.

**False positive analysis**

* Legitimate software installations or updates may modify the ReflectDebugger registry key as part of their error reporting configuration. Users can create exceptions for known software vendors by verifying the digital signature of the executable associated with the change.
* System administrators may intentionally configure the ReflectDebugger for debugging purposes. Document and whitelist these changes in the security monitoring system to prevent unnecessary alerts.
* Automated system maintenance tools might interact with the ReflectDebugger registry key. Identify and exclude these tools by correlating the registry changes with scheduled maintenance activities.
* Security software or endpoint protection solutions may alter the ReflectDebugger settings as part of their protective measures. Confirm these changes with the security vendor and add them to the exclusion list if deemed safe.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further execution of malicious code via the Werfault ReflectDebugger.
* Terminate any suspicious processes associated with Werfault that are running with the "-pr" parameter to halt potential malicious activity.
* Remove unauthorized entries from the registry path "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger" to eliminate persistence mechanisms.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection tools to identify and remove any additional malware or malicious artifacts.
* Review and restore any system or application configurations that may have been altered by the attacker to their original state.
* Escalate the incident to the security operations team for further analysis and to determine if additional systems are affected.
* Implement enhanced monitoring and alerting for registry changes in the specified paths to detect and respond to similar threats in the future.


## Rule query [_rule_query_1222]

```js
registry where host.os.type == "windows" and event.type == "change" and
  registry.path : (
    "HKLM\\Software\\Microsoft\\Windows\\Windows Error Reporting\\Hangs\\ReflectDebugger",
    "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows\\Windows Error Reporting\\Hangs\\ReflectDebugger",
    "MACHINE\\Software\\Microsoft\\Windows\\Windows Error Reporting\\Hangs\\ReflectDebugger"
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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



