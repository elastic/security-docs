---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/command-and-scripting-interpreter-via-windows-scripts.html
---

# Command and Scripting Interpreter via Windows Scripts [command-and-scripting-interpreter-via-windows-scripts]

Identifies PowerShell.exe or Cmd.exe execution spawning from Windows Script Host processes Wscript.exe.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*
* logs-system.security*
* logs-windows.sysmon_operational-*
* logs-sentinel_one_cloud_funnel.*
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
* Tactic: Execution
* Data Source: System
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Microsoft Defender for Endpoint
* Resources: Investigation Guide

**Version**: 202

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_227]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Command and Scripting Interpreter via Windows Scripts**

PowerShell, a powerful scripting language in Windows, is often targeted by adversaries for executing malicious scripts. Attackers exploit Windows Script Host processes like cscript or wscript to launch PowerShell with obfuscated commands, evading detection. The detection rule identifies such suspicious activity by monitoring PowerShell executions with specific patterns and parent processes, while filtering out known legitimate use cases to reduce false positives.

**Possible investigation steps**

* Review the process command line and arguments to identify any obfuscation patterns or suspicious commands, such as Base64 encoding or web requests, that match the query’s suspicious patterns.
* Examine the parent process details, specifically focusing on wscript.exe, cscript.exe, or mshta.exe, to determine if the PowerShell execution was initiated by a legitimate script or a potentially malicious one.
* Check the process execution context, including the user account and host, to assess if the activity aligns with expected behavior for that user or system.
* Investigate any network connections or file downloads initiated by the PowerShell process, especially those involving external IP addresses or domains, to identify potential data exfiltration or further malicious activity.
* Correlate the alert with other security events or logs from the same host or user to identify any preceding or subsequent suspicious activities that could indicate a broader attack campaign.

**False positive analysis**

* Legitimate PowerShell commands using non-shortened execution flags may trigger false positives. To manage this, exclude processes with arguments like "-EncodedCommand", "Import-Module*", and "-NonInteractive" unless they are associated with suspicious activity.
* Third-party installation scripts, such as those related to Microsoft System Center or WebLogic, can cause false positives. Exclude these by filtering out specific parent process arguments or command lines, such as "Microsoft.SystemCenter.ICMPProbe.WithConsecutiveSamples.vbs" and "WEBLOGIC_ARGS_CURRENT_1.DATA".
* Routine administrative tasks, like gathering network information, may be flagged. Exclude known scripts like "gatherNetworkInfo.vbs" from detection to prevent unnecessary alerts.
* Exclude specific user scripts or tools that are known to be safe, such as those located in user directories like "C:\Users\Prestige\AppData\Local\Temp\Rar$*\KMS_VL_ALL_AIO.cmd" if they are verified as non-malicious.
* Regularly review and update exclusion lists to ensure they reflect current legitimate activities and do not inadvertently allow new threats.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious PowerShell processes identified by the alert to stop ongoing malicious execution.
* Conduct a thorough review of the affected system’s PowerShell execution logs to identify any additional malicious scripts or commands that may have been executed.
* Remove any malicious scripts or files identified during the investigation from the system to prevent re-execution.
* Restore the system from a known good backup if any critical system files or configurations have been altered by the malicious activity.
* Update and patch the system to the latest security standards to close any vulnerabilities that may have been exploited.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.


## Rule query [_rule_query_235]

```js
process where host.os.type == "windows" and event.action == "start" and
  process.name : ("powershell.exe", "pwsh.exe", "cmd.exe") and
  process.parent.name : ("wscript.exe", "mshta.exe") and ?process.parent.args : "?:\\Users\\*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: PowerShell
    * ID: T1059.001
    * Reference URL: [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)

* Sub-technique:

    * Name: Windows Command Shell
    * ID: T1059.003
    * Reference URL: [https://attack.mitre.org/techniques/T1059/003/](https://attack.mitre.org/techniques/T1059/003/)

* Sub-technique:

    * Name: Visual Basic
    * ID: T1059.005
    * Reference URL: [https://attack.mitre.org/techniques/T1059/005/](https://attack.mitre.org/techniques/T1059/005/)



