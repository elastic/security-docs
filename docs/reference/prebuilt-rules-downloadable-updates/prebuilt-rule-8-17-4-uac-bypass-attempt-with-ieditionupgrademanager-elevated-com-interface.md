---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-uac-bypass-attempt-with-ieditionupgrademanager-elevated-com-interface.html
---

# UAC Bypass Attempt with IEditionUpgradeManager Elevated COM Interface [prebuilt-rule-8-17-4-uac-bypass-attempt-with-ieditionupgrademanager-elevated-com-interface]

Identifies attempts to bypass User Account Control (UAC) by abusing an elevated COM Interface to launch a rogue Windows ClipUp program. Attackers may attempt to bypass UAC to stealthily execute code with elevated permissions.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/hfiref0x/UACME](https://github.com/hfiref0x/UACME)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Tactic: Defense Evasion
* Tactic: Execution
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

## Investigation guide [_investigation_guide_4979]

**Triage and analysis**

[TBC: QUOTE]
**Investigating UAC Bypass Attempt with IEditionUpgradeManager Elevated COM Interface**

User Account Control (UAC) is a security feature in Windows designed to prevent unauthorized changes by prompting for elevated permissions. The IEditionUpgradeManager COM interface can be exploited by attackers to bypass UAC, allowing them to execute code with elevated privileges without user consent. This detection rule identifies such attempts by monitoring for the execution of the ClipUp program from non-standard paths, initiated by a specific COM interface, indicating potential misuse for privilege escalation.

**Possible investigation steps**

* Review the process execution details to confirm the presence of ClipUp.exe running from a non-standard path, as indicated by the process.executable field not matching "C:\Windows\System32\ClipUp.exe".
* Investigate the parent process, dllhost.exe, to determine if it was legitimately initiated or if it shows signs of compromise, focusing on the process.parent.args field to verify the use of the specific COM interface CLSID: `/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}`.
* Check the user account context under which ClipUp.exe was executed to assess if it aligns with expected user behavior or if it suggests unauthorized access.
* Correlate this event with other security logs and alerts from data sources like Elastic Endgame, Elastic Defend, Sysmon, Microsoft Defender for Endpoint, or SentinelOne to identify any related suspicious activities or patterns.
* Examine recent changes or anomalies in system configurations or installed software that might indicate preparation for or execution of a UAC bypass attempt.
* If available, review network activity logs for any unusual outbound connections or data exfiltration attempts following the execution of ClipUp.exe.

**False positive analysis**

* Legitimate software updates or installations may trigger the rule if they temporarily use non-standard paths for ClipUp.exe. Verify the source and purpose of the process to determine if it is part of a legitimate update or installation.
* Custom scripts or administrative tools that utilize ClipUp.exe from non-standard paths for legitimate purposes can cause false positives. Review the script or tool usage and consider excluding these specific paths if they are verified as safe.
* Software testing environments where ClipUp.exe is executed from non-standard paths for testing purposes may trigger the rule. Implement exclusions for known testing environments to prevent unnecessary alerts.
* Automated deployment tools that use ClipUp.exe from non-standard paths as part of their deployment process can be mistaken for malicious activity. Confirm the deployment tool’s behavior and add exceptions for its known operations.
* In environments where multiple users have administrative privileges, legitimate administrative actions might inadvertently match the rule’s criteria. Regularly audit administrative actions and consider excluding known benign activities.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Terminate the ClipUp.exe process if it is running from a non-standard path to stop any ongoing malicious activity.
* Conduct a thorough review of the system’s recent activity logs to identify any additional unauthorized changes or suspicious behavior.
* Restore any altered system files or configurations to their original state using known good backups or system restore points.
* Update and patch the operating system and all installed software to the latest versions to mitigate known vulnerabilities.
* Implement application whitelisting to prevent unauthorized programs from executing, focusing on blocking non-standard paths for critical system executables.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the potential impact on other systems within the network.


## Rule query [_rule_query_5934]

```js
process where host.os.type == "windows" and event.type == "start" and process.name : "Clipup.exe" and
  not process.executable : "C:\\Windows\\System32\\ClipUp.exe" and process.parent.name : "dllhost.exe" and
  /* CLSID of the Elevated COM Interface IEditionUpgradeManager */
  process.parent.args : "/Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Bypass User Account Control
    * ID: T1548.002
    * Reference URL: [https://attack.mitre.org/techniques/T1548/002/](https://attack.mitre.org/techniques/T1548/002/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Bypass User Account Control
    * ID: T1548.002
    * Reference URL: [https://attack.mitre.org/techniques/T1548/002/](https://attack.mitre.org/techniques/T1548/002/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Inter-Process Communication
    * ID: T1559
    * Reference URL: [https://attack.mitre.org/techniques/T1559/](https://attack.mitre.org/techniques/T1559/)

* Sub-technique:

    * Name: Component Object Model
    * ID: T1559.001
    * Reference URL: [https://attack.mitre.org/techniques/T1559/001/](https://attack.mitre.org/techniques/T1559/001/)



