---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/privilege-escalation-via-windir-environment-variable.html
---

# Privilege Escalation via Windir Environment Variable [privilege-escalation-via-windir-environment-variable]

Identifies a privilege escalation attempt via a rogue Windows directory (Windir) environment variable. This is a known primitive that is often combined with other vulnerabilities to elevate privileges.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.registry-*
* endgame-*
* logs-windows.sysmon_operational-*
* winlogbeat-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html](https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 309

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_823]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Privilege Escalation via Windir Environment Variable**

The Windir environment variable points to the Windows directory, crucial for system operations. Adversaries may alter this variable to redirect processes to malicious directories, gaining elevated privileges. The detection rule monitors changes to this variable in the registry, flagging deviations from expected paths like "C:\windows," thus identifying potential privilege escalation attempts.

**Possible investigation steps**

* Review the registry change event details to identify the specific user account associated with the altered Windir or SystemRoot environment variable. This can be done by examining the registry path and user context in the event data.
* Check the registry data strings to determine the new path set for the Windir or SystemRoot variable. Investigate if this path points to a known malicious directory or an unexpected location.
* Correlate the event with other recent registry changes or system events on the same host to identify any patterns or additional suspicious activities that might indicate a broader attack.
* Investigate the process or application that initiated the registry change by reviewing process creation logs or command-line arguments around the time of the event. This can help identify the source of the change.
* Assess the affected system for any signs of compromise or unauthorized access, such as unusual network connections, unexpected running processes, or new user accounts.
* Consult threat intelligence sources to determine if the observed behavior matches any known attack patterns or campaigns, particularly those involving privilege escalation techniques.
* If possible, restore the Windir or SystemRoot environment variable to its expected value and monitor the system for any further unauthorized changes.

**False positive analysis**

* System updates or patches may temporarily alter the Windir environment variable. Monitor for these events during known maintenance windows and consider excluding them from alerts.
* Custom scripts or applications that modify environment variables for legitimate purposes can trigger false positives. Identify these scripts and whitelist their activity in the detection rule.
* User profile migrations or system restorations might change the Windir path. Exclude these operations if they are part of routine IT processes.
* Virtual environments or sandboxed applications may use different Windir paths. Verify these environments and adjust the detection rule to accommodate their specific configurations.
* Administrative tools that modify user environments for configuration management can cause alerts. Document these tools and create exceptions for their expected behavior.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement.
* Revert the Windir environment variable to its legitimate value, typically "C:\windows", to restore normal system operations.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any malicious software or scripts.
* Review recent user activity and system logs to identify any unauthorized access or changes, focusing on the time frame around the detected registry change.
* Reset passwords for any user accounts that may have been compromised, especially those with elevated privileges.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring on the affected system and similar endpoints to detect any further attempts to alter critical environment variables or other suspicious activities.


## Rule query [_rule_query_877]

```js
registry where host.os.type == "windows" and event.type == "change" and
registry.value : ("windir", "systemroot") and
registry.path : (
    "HKEY_USERS\\*\\Environment\\windir",
    "HKEY_USERS\\*\\Environment\\systemroot",
    "HKU\\*\\Environment\\windir",
    "HKU\\*\\Environment\\systemroot",
    "HKCU\\*\\Environment\\windir",
    "HKCU\\*\\Environment\\systemroot",
    "\\REGISTRY\\USER\\*\\Environment\\windir",
    "\\REGISTRY\\USER\\*\\Environment\\systemroot",
    "USER\\*\\Environment\\windir",
    "USER\\*\\Environment\\systemroot"
    ) and
 not registry.data.strings : ("C:\\windows", "%SystemRoot%")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Path Interception by PATH Environment Variable
    * ID: T1574.007
    * Reference URL: [https://attack.mitre.org/techniques/T1574/007/](https://attack.mitre.org/techniques/T1574/007/)



