---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/full-user-mode-dumps-enabled-system-wide.html
---

# Full User-Mode Dumps Enabled System-Wide [full-user-mode-dumps-enabled-system-wide]

Identifies the enable of the full user-mode dumps feature system-wide. This feature allows Windows Error Reporting (WER) to collect data after an application crashes. This setting is a requirement for the LSASS Shtinkering attack, which fakes the communication of a crash on LSASS, generating a dump of the process memory, which gives the attacker access to the credentials present on the system without having to bring malware to the system. This setting is not enabled by default, and applications must create their registry subkeys to hold settings that enable them to collect dumps.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.registry-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps](https://docs.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps)
* [https://github.com/deepinstinct/Lsass-Shtinkering](https://github.com/deepinstinct/Lsass-Shtinkering)
* [https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf](https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Asaf%20Gilboa%20-%20LSASS%20Shtinkering%20Abusing%20Windows%20Error%20Reporting%20to%20Dump%20LSASS.pdf)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Resources: Investigation Guide

**Version**: 109

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_352]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Full User-Mode Dumps Enabled System-Wide**

Full user-mode dumps are a diagnostic feature in Windows that captures detailed information about application crashes, aiding in troubleshooting. However, attackers can exploit this by triggering dumps of sensitive processes like LSASS to extract credentials. The detection rule identifies registry changes enabling this feature system-wide, flagging potential misuse by excluding legitimate system processes, thus alerting analysts to suspicious activity.

**Possible investigation steps**

* Review the registry path HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\DumpType to confirm if the value is set to "2" or "0x00000002", indicating full user-mode dumps are enabled.
* Check for any recent changes to the registry key by examining the modification timestamps and identifying the user or process responsible for the change.
* Investigate the context of the alert by reviewing recent process execution logs to identify any suspicious processes that may have triggered the dump, especially those not matching the legitimate svchost.exe process with user IDs S-1-5-18, S-1-5-19, or S-1-5-20.
* Analyze any generated dump files for sensitive information, such as credentials, and determine if they were accessed or exfiltrated by unauthorized users or processes.
* Correlate the alert with other security events or logs, such as Sysmon or Microsoft Defender for Endpoint, to identify any related suspicious activities or patterns that could indicate a broader attack.

**False positive analysis**

* Legitimate system processes like svchost.exe may trigger the rule if they are not properly excluded. Ensure that the exclusion for svchost.exe is correctly configured by verifying the process executable path and user IDs.
* Custom applications that require full user-mode dumps for legitimate debugging purposes might be flagged. Identify these applications and create specific registry subkey exclusions to prevent false positives.
* System administrators performing routine maintenance or diagnostics might enable full user-mode dumps temporarily. Document these activities and consider creating temporary exceptions during maintenance windows.
* Security tools or monitoring software that simulate crash scenarios for testing purposes could trigger the rule. Verify the legitimacy of these tools and add them to an exclusion list if they are part of regular security operations.
* Updates or patches from software vendors that modify registry settings for error reporting might be misinterpreted as suspicious. Monitor update schedules and correlate any rule triggers with known update activities to avoid unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further credential access or lateral movement by the attacker.
* Terminate any unauthorized processes that are generating full user-mode dumps, especially those related to LSASS, to stop further credential dumping.
* Conduct a thorough review of the registry settings on the affected system to ensure that the full user-mode dumps feature is disabled unless explicitly required for legitimate purposes.
* Change all credentials that may have been exposed, particularly those associated with high-privilege accounts, to mitigate the risk of unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and alerting for similar registry changes across the network to detect and respond to future attempts promptly.
* Review and update endpoint protection configurations to ensure they are capable of detecting and blocking similar credential dumping techniques.


## Rule query [_rule_query_384]

```js
registry where host.os.type == "windows" and
    registry.path : (
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\DumpType",
        "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\DumpType"
    ) and
    registry.data.strings : ("2", "0x00000002") and
    not (process.executable : "?:\\Windows\\system32\\svchost.exe" and user.id : ("S-1-5-18", "S-1-5-19", "S-1-5-20"))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)



