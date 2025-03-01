---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/uac-bypass-via-icmluautil-elevated-com-interface.html
---

# UAC Bypass via ICMLuaUtil Elevated COM Interface [uac-bypass-via-icmluautil-elevated-com-interface]

Identifies User Account Control (UAC) bypass attempts via the ICMLuaUtil Elevated COM interface. Attackers may attempt to bypass UAC to stealthily execute code with elevated permissions.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

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
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1086]

**Triage and analysis**

[TBC: QUOTE]
**Investigating UAC Bypass via ICMLuaUtil Elevated COM Interface**

The ICMLuaUtil Elevated COM Interface is a Windows component that facilitates User Account Control (UAC) operations, allowing certain processes to execute with elevated privileges. Adversaries exploit this by invoking the interface to bypass UAC, executing malicious code stealthily. The detection rule identifies such attempts by monitoring processes initiated by `dllhost.exe` with specific arguments, excluding legitimate processes like `WerFault.exe`, thus flagging potential privilege escalation activities.

**Possible investigation steps**

* Review the process tree to identify the parent and child processes of the flagged `dllhost.exe` instance to understand the context of its execution.
* Examine the command-line arguments of the `dllhost.exe` process to confirm the presence of the suspicious `/Processid:{{3E5FC7F9-9A51-4367-9063-A120244FBEC7}}` or `/Processid:{{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}}` arguments.
* Check for any recent changes or installations on the system that might have introduced the suspicious behavior, focusing on software that might interact with UAC settings.
* Investigate the user account under which the `dllhost.exe` process was executed to determine if it has been compromised or if it has elevated privileges.
* Correlate the event with other security logs or alerts from data sources like Sysmon or Microsoft Defender for Endpoint to identify any related suspicious activities or patterns.
* Assess the network activity of the affected system around the time of the alert to detect any potential data exfiltration or communication with known malicious IP addresses.

**False positive analysis**

* Legitimate software updates or installations may trigger the rule if they use the ICMLuaUtil Elevated COM Interface for necessary elevation. Users can monitor the specific software involved and create exceptions for trusted applications.
* System maintenance tasks initiated by IT administrators might use similar processes for legitimate purposes. Identifying these tasks and excluding them from the rule can reduce false positives.
* Certain enterprise applications may require elevated privileges and use the same COM interface. Regularly review and whitelist these applications to prevent unnecessary alerts.
* Automated scripts or tools used for system management that invoke the interface should be evaluated. If deemed safe, they can be added to an exclusion list to avoid repeated false positives.
* Regularly update the list of excluded processes to reflect changes in the organization’s software environment, ensuring that only non-threatening behaviors are excluded.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes initiated by `dllhost.exe` with the specified arguments to stop the execution of potentially malicious code.
* Conduct a thorough review of the affected system to identify any unauthorized changes or additional malicious files, and remove them.
* Restore the system from a known good backup if any critical system files or configurations have been altered.
* Update and patch the operating system and all installed software to mitigate any known vulnerabilities that could be exploited for UAC bypass.
* Implement application whitelisting to prevent unauthorized applications from executing, focusing on blocking the execution of `dllhost.exe` with suspicious arguments.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the potential impact on the broader network.


## Rule query [_rule_query_1142]

```js
process where host.os.type == "windows" and event.type == "start" and
 process.parent.name == "dllhost.exe" and
 process.parent.args in ("/Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}", "/Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}") and
 process.pe.original_file_name != "WerFault.exe"
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



