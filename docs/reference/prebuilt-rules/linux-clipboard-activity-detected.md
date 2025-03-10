---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/linux-clipboard-activity-detected.html
---

# Linux Clipboard Activity Detected [linux-clipboard-activity-detected]

This rule monitors for the usage of the most common clipboard utilities on unix systems by an uncommon process group leader. Adversaries may collect data stored in the clipboard from users copying information within or between applications.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Collection
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Resources: Investigation Guide

**Version**: 6

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_473]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Linux Clipboard Activity Detected**

Clipboard utilities on Linux, such as xclip and xsel, facilitate data transfer between applications by storing copied content temporarily. Adversaries exploit this by capturing sensitive data copied by users. The detection rule identifies unusual clipboard activity by monitoring processes that start these utilities, excluding common parent processes, to flag potential misuse. This helps in identifying unauthorized data collection attempts.

**Possible investigation steps**

* Review the alert details to identify the specific process name that triggered the alert, focusing on clipboard utilities like xclip, xsel, wl-clipboard, clipman, or copyq.
* Examine the parent process of the detected clipboard utility to understand the context of its execution, ensuring it is not a common parent process like bwrap or micro.
* Investigate the user account associated with the process to determine if the activity aligns with their typical behavior or if it appears suspicious.
* Check the timing and frequency of the clipboard utility’s execution to assess if it coincides with any known user activities or if it suggests automated or unauthorized access.
* Analyze any related process events or logs around the time of the alert to identify potential data exfiltration attempts or other malicious activities.
* Consider correlating this alert with other security events or alerts to identify patterns or broader attack campaigns targeting clipboard data.

**False positive analysis**

* Frequent use of clipboard utilities by legitimate applications or scripts can trigger false positives. Identify and document these applications to create exceptions in the detection rule.
* Developers and system administrators often use clipboard utilities in automated scripts. Review and whitelist these scripts to prevent unnecessary alerts.
* Some desktop environments or window managers may use clipboard utilities as part of their normal operation. Monitor and exclude these processes if they are verified as non-threatening.
* Regular user activities involving clipboard utilities for productivity tasks can be mistaken for suspicious behavior. Educate users on safe practices and adjust the rule to exclude known benign parent processes.
* Consider the context of the clipboard utility usage, such as time of day or user role, to refine detection criteria and reduce false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent potential data exfiltration or further unauthorized access.
* Terminate any suspicious processes identified as running clipboard utilities without a common parent process, such as xclip or xsel, to stop potential data capture.
* Conduct a thorough review of recent clipboard activity logs to identify any sensitive data that may have been captured and assess the potential impact.
* Change passwords and rotate any credentials that may have been copied to the clipboard recently to mitigate the risk of credential theft.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement additional monitoring on the affected system to detect any further unauthorized clipboard activity or related suspicious behavior.
* Review and update endpoint security configurations to ensure that only authorized processes can access clipboard utilities, reducing the risk of future exploitation.


## Rule query [_rule_query_508]

```js
event.category:process and host.os.type:"linux" and event.type:"start" and
event.action:("exec" or "exec_event" or "executed" or "process_started") and
process.name:("xclip" or "xsel" or "wl-clipboard" or "clipman" or "copyq") and
not process.parent.name:("bwrap" or "micro")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Clipboard Data
    * ID: T1115
    * Reference URL: [https://attack.mitre.org/techniques/T1115/](https://attack.mitre.org/techniques/T1115/)



