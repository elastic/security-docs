---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-net-code-compilation.html
---

# Suspicious .NET Code Compilation [prebuilt-rule-8-17-4-suspicious-net-code-compilation]

Identifies executions of .NET compilers with suspicious parent processes, which can indicate an attacker’s attempt to compile code after delivery in order to bypass security mechanisms.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-crowdstrike.fdr*

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
* Tactic: Defense Evasion
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 313

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4757]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious .NET Code Compilation**

**Possible investigation steps**

* Review the process tree to understand the relationship between the suspicious parent process (e.g., wscript.exe, mshta.exe) and the .NET compiler process (csc.exe or vbc.exe) to determine if the execution flow is typical or anomalous.
* Examine the command-line arguments used by the .NET compiler process to identify any potentially malicious code or scripts being compiled.
* Check the user account associated with the process execution to determine if it aligns with expected behavior or if it indicates potential compromise or misuse.
* Investigate the source and integrity of the parent process executable to ensure it has not been tampered with or replaced by a malicious version.
* Correlate the event with other security alerts or logs from the same host or user to identify any patterns or additional indicators of compromise.
* Analyze network activity from the host around the time of the alert to detect any suspicious outbound connections that may indicate data exfiltration or command-and-control communication.

**False positive analysis**

* Legitimate software development activities may trigger this rule if developers use scripting engines or system utilities to automate the compilation of .NET code. To manage this, identify and whitelist known development environments or scripts that frequently compile code using these methods.
* System administrators might use scripts or automation tools that invoke .NET compilers for maintenance tasks. Review and document these processes, then create exceptions for recognized administrative scripts to prevent unnecessary alerts.
* Some enterprise applications may use .NET compilers as part of their normal operation, especially if they dynamically generate or compile code. Investigate these applications and exclude their processes from the rule if they are verified as non-threatening.
* Security tools or monitoring solutions might simulate suspicious behavior for testing purposes, which could trigger this rule. Coordinate with your security team to identify such tools and exclude their activities from detection.
* In environments where custom scripts are frequently used for deployment or configuration, ensure these scripts are reviewed and, if safe, added to an exclusion list to reduce false positives.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further execution or spread of potentially malicious code.
* Terminate any suspicious processes identified, such as `csc.exe` or `vbc.exe`, that are running with unusual parent processes.
* Conduct a thorough scan of the isolated system using updated antivirus and endpoint detection tools to identify and remove any malicious files or remnants.
* Review and analyze the execution logs to determine the source and scope of the threat, focusing on the parent processes like `wscript.exe` or `mshta.exe` that initiated the compiler execution.
* Restore the system from a known good backup if malicious activity is confirmed and cannot be fully remediated through cleaning.
* Implement application whitelisting to prevent unauthorized execution of compilers and scripting engines by non-standard parent processes.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the need for broader organizational response measures.


## Rule query [_rule_query_5712]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.name : ("csc.exe", "vbc.exe") and
  process.parent.name : ("wscript.exe", "mshta.exe", "cscript.exe", "wmic.exe", "svchost.exe", "rundll32.exe", "cmstp.exe", "regsvr32.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Obfuscated Files or Information
    * ID: T1027
    * Reference URL: [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)

* Sub-technique:

    * Name: Compile After Delivery
    * ID: T1027.004
    * Reference URL: [https://attack.mitre.org/techniques/T1027/004/](https://attack.mitre.org/techniques/T1027/004/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Visual Basic
    * ID: T1059.005
    * Reference URL: [https://attack.mitre.org/techniques/T1059/005/](https://attack.mitre.org/techniques/T1059/005/)



