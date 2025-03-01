---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-explorer-child-process.html
---

# Suspicious Explorer Child Process [prebuilt-rule-8-17-4-suspicious-explorer-child-process]

Identifies a suspicious Windows explorer child process. Explorer.exe can be abused to launch malicious scripts or executables from a trusted parent process.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
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
* Tactic: Initial Access
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

## Investigation guide [_investigation_guide_4875]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Explorer Child Process**

Windows Explorer, a core component of the Windows OS, manages file and folder navigation. Adversaries exploit its trusted status to launch malicious scripts or executables, often using DCOM to start processes like PowerShell or cmd.exe. The detection rule identifies such anomalies by monitoring child processes of Explorer with specific characteristics, excluding known benign activities, to flag potential threats.

**Possible investigation steps**

* Review the process details to confirm the suspicious child process was indeed started by explorer.exe with the specific parent arguments indicating DCOM usage, such as "-Embedding".
* Check the process command line arguments and execution context to identify any potentially malicious scripts or commands being executed by the child process.
* Investigate the parent process explorer.exe to determine if it was started by a legitimate user action or if there are signs of compromise, such as unusual user activity or recent phishing attempts.
* Correlate the event with other security logs or alerts from data sources like Microsoft Defender for Endpoint or Sysmon to identify any related suspicious activities or patterns.
* Examine the network activity associated with the suspicious process to detect any unauthorized data exfiltration or communication with known malicious IP addresses.
* Assess the system for any additional indicators of compromise, such as unexpected changes in system files or registry keys, which might suggest a broader attack.

**False positive analysis**

* Legitimate software installations or updates may trigger the rule when they use scripts or executables like PowerShell or cmd.exe. Users can create exceptions for known software update processes by identifying their specific command-line arguments or parent process details.
* System administrators often use scripts for maintenance tasks that might be flagged by this rule. To prevent false positives, administrators should document and exclude these routine scripts by specifying their unique process arguments or execution times.
* Some enterprise applications may use DCOM to launch processes for legitimate purposes. Users should identify these applications and exclude their specific process signatures or parent-child process relationships from the rule.
* Automated testing environments might execute scripts or commands that resemble suspicious activity. Users can mitigate false positives by excluding processes that are part of known testing frameworks or environments.
* Certain security tools or monitoring software may use similar techniques to gather system information. Users should verify and exclude these tools by confirming their process names and execution patterns.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of the potential threat and to contain any malicious activity.
* Terminate the suspicious child process identified in the alert, such as cscript.exe, wscript.exe, powershell.exe, rundll32.exe, cmd.exe, mshta.exe, or regsvr32.exe, to stop any ongoing malicious actions.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or processes.
* Review and analyze the parent process explorer.exe and its command-line arguments to understand how the malicious process was initiated and to identify any potential persistence mechanisms.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat is part of a larger attack campaign.
* Implement additional monitoring and alerting for similar suspicious activities involving explorer.exe to enhance detection capabilities and prevent recurrence.
* Review and update endpoint security policies to restrict the execution of potentially malicious scripts or executables from explorer.exe, especially when initiated via DCOM.


## Rule query [_rule_query_5830]

```js
process where host.os.type == "windows" and event.type == "start" and
  (
   process.name : ("cscript.exe", "wscript.exe", "powershell.exe", "rundll32.exe", "cmd.exe", "mshta.exe", "regsvr32.exe") or
   ?process.pe.original_file_name in ("cscript.exe", "wscript.exe", "PowerShell.EXE", "RUNDLL32.EXE", "Cmd.Exe", "MSHTA.EXE", "REGSVR32.EXE")
  ) and
  /* Explorer started via DCOM */
  process.parent.name : "explorer.exe" and process.parent.args : "-Embedding" and
  not process.parent.args:
          (
            /* Noisy CLSID_SeparateSingleProcessExplorerHost Explorer COM Class IDs   */
            "/factory,{5BD95610-9434-43C2-886C-57852CC8A120}",
            "/factory,{ceff45ee-c862-41de-aee2-a022c81eda92}"
          )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Attachment
    * ID: T1566.001
    * Reference URL: [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)

* Sub-technique:

    * Name: Spearphishing Link
    * ID: T1566.002
    * Reference URL: [https://attack.mitre.org/techniques/T1566/002/](https://attack.mitre.org/techniques/T1566/002/)

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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)



