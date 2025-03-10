---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-werfault-child-process.html
---

# Suspicious WerFault Child Process [prebuilt-rule-8-17-4-suspicious-werfault-child-process]

A suspicious WerFault child process was detected, which may indicate an attempt to run via the SilentProcessExit registry key manipulation. Verify process details such as command line, network connections and file writes.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-sentinel_one_cloud_funnel.*
* logs-m365_defender.event-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.hexacorn.com/blog/2019/09/19/silentprocessexit-quick-look-under-the-hood/](https://www.hexacorn.com/blog/2019/09/19/silentprocessexit-quick-look-under-the-hood/)
* [https://www.hexacorn.com/blog/2019/09/20/werfault-command-line-switches-v0-1/](https://www.hexacorn.com/blog/2019/09/20/werfault-command-line-switches-v0-1/)
* [https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/persistence_SilentProcessExit_ImageHijack_sysmon_13_1.evtx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/persistence_SilentProcessExit_ImageHijack_sysmon_13_1.evtx)
* [http://web.archive.org/web/20230530011556/https://blog.menasec.net/2021/01/](http://web.archive.org/web/20230530011556/https://blog.menasec.net/2021/01/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Persistence
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 416

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4776]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious WerFault Child Process**

WerFault.exe is a Windows error reporting tool that handles application crashes. Adversaries may exploit it by manipulating the SilentProcessExit registry key to execute malicious processes stealthily. The detection rule identifies unusual child processes of WerFault.exe, focusing on specific command-line arguments indicative of this abuse, while excluding known legitimate executables, thus highlighting potential threats.

**Possible investigation steps**

* Review the command line arguments of the suspicious child process to confirm the presence of "-s", "-t", and "-c" flags, which indicate potential abuse of the SilentProcessExit mechanism.
* Examine the process executable path to ensure it is not one of the known legitimate executables ("?:\Windows\SysWOW64\Initcrypt.exe", "?:\Program Files (x86)\Heimdal\Heimdal.Guard.exe") that are excluded from the detection rule.
* Investigate the network connections established by the suspicious process to identify any unusual or unauthorized external communications.
* Analyze file writes and modifications made by the process to detect any unauthorized changes or potential indicators of compromise.
* Check the parent process tree to understand the context of how WerFault.exe was invoked and identify any preceding suspicious activities or processes.
* Correlate the event with other security alerts or logs from data sources like Elastic Endgame, Elastic Defend, Microsoft Defender for Endpoint, Sysmon, or SentinelOne to gather additional context and assess the scope of the potential threat.

**False positive analysis**

* Legitimate software updates or installations may trigger WerFault.exe with command-line arguments similar to those used in the SilentProcessExit mechanism. Users should verify the digital signature of the executable and check if it aligns with known update processes.
* Security software or system management tools might use WerFault.exe for legitimate purposes. Users can create exceptions for these known tools by adding their executables to the exclusion list in the detection rule.
* Custom scripts or enterprise applications that utilize WerFault.exe for error handling could be flagged. Review the process details and, if verified as non-threatening, add these scripts or applications to the exclusion list.
* Frequent occurrences of the same process being flagged can indicate a benign pattern. Users should monitor these patterns and, if consistently verified as safe, update the rule to exclude these specific processes.

**Response and remediation**

* Isolate the affected system from the network to prevent further potential malicious activity and lateral movement.
* Terminate the suspicious child process of WerFault.exe immediately to halt any ongoing malicious actions.
* Conduct a thorough review of the SilentProcessExit registry key to identify and remove any unauthorized entries that may have been used to execute the malicious process.
* Restore any altered or deleted files from a known good backup to ensure system integrity and recover any lost data.
* Update and run a full antivirus and anti-malware scan on the affected system to detect and remove any additional threats or remnants of the attack.
* Monitor network traffic and system logs for any signs of persistence mechanisms or further attempts to exploit the SilentProcessExit mechanism.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Rule query [_rule_query_5731]

```js
process where host.os.type == "windows" and event.type == "start" and

  process.parent.name : "WerFault.exe" and

  /* args -s and -t used to execute a process via SilentProcessExit mechanism */
  (process.parent.args : "-s" and process.parent.args : "-t" and process.parent.args : "-c") and

  not process.executable : ("?:\\Windows\\SysWOW64\\Initcrypt.exe", "?:\\Program Files (x86)\\Heimdal\\Heimdal.Guard.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Image File Execution Options Injection
    * ID: T1546.012
    * Reference URL: [https://attack.mitre.org/techniques/T1546/012/](https://attack.mitre.org/techniques/T1546/012/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Image File Execution Options Injection
    * ID: T1546.012
    * Reference URL: [https://attack.mitre.org/techniques/T1546/012/](https://attack.mitre.org/techniques/T1546/012/)



