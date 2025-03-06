---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-command-execution-via-solarwinds-process.html
---

# Command Execution via SolarWinds Process [prebuilt-rule-8-17-4-command-execution-via-solarwinds-process]

A suspicious SolarWinds child process (Cmd.exe or Powershell.exe) was detected.

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

**References**:

* [https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)
* [https://github.com/mandiant/sunburst_countermeasures/blob/main/rules/SUNBURST/hxioc/SUNBURST%20SUSPICIOUS%20FILEWRITES%20(METHODOLOGY).ioc](https://github.com/mandiant/sunburst_countermeasures/blob/main/rules/SUNBURST/hxioc/SUNBURST%20SUSPICIOUS%20FILEWRITES%20(METHODOLOGY).ioc)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Tactic: Initial Access
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 314

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4831]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Command Execution via SolarWinds Process**

SolarWinds is a widely used IT management tool that can be targeted by adversaries to execute unauthorized commands. Attackers may exploit SolarWinds processes to launch command-line interpreters like Cmd.exe or Powershell.exe, potentially leading to system compromise. The detection rule identifies suspicious child processes initiated by specific SolarWinds executables, flagging potential misuse by correlating process start events with known SolarWinds parent processes. This helps in early detection of malicious activities leveraging SolarWinds for command execution.

**Possible investigation steps**

* Review the alert details to identify the specific SolarWinds parent process that initiated the suspicious child process (Cmd.exe or Powershell.exe) and note the exact executable name and path.
* Examine the timeline of events around the process start event to identify any preceding or subsequent suspicious activities, such as unusual network connections or file modifications.
* Check the user account associated with the process execution to determine if it aligns with expected behavior or if it indicates potential compromise or misuse.
* Investigate the command line arguments used by the child process to assess if they contain any malicious or unexpected commands.
* Correlate the event with other security logs and alerts from data sources like Microsoft Defender for Endpoint or Sysmon to gather additional context and identify potential patterns of malicious behavior.
* Assess the system’s current state for any indicators of compromise, such as unauthorized changes to system configurations or the presence of known malware signatures.

**False positive analysis**

* Routine administrative tasks using SolarWinds may trigger the rule when legitimate scripts are executed via Cmd.exe or Powershell.exe. Users can create exceptions for known maintenance scripts or tasks that are regularly scheduled and verified as safe.
* Automated updates or patches initiated by SolarWinds processes might be flagged. To mitigate this, users should whitelist specific update processes or scripts that are part of the regular update cycle.
* Monitoring or diagnostic activities performed by IT staff using SolarWinds tools can result in false positives. Establish a baseline of normal activities and exclude these from alerts by identifying and documenting regular diagnostic commands.
* Custom scripts developed for internal use that leverage SolarWinds processes could be misidentified as threats. Ensure these scripts are reviewed and approved, then add them to an exception list to prevent unnecessary alerts.
* Third-party integrations with SolarWinds that require command execution might be mistakenly flagged. Verify the legitimacy of these integrations and exclude their associated processes from detection rules.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized command execution and potential lateral movement.
* Terminate any suspicious child processes such as Cmd.exe or Powershell.exe that were initiated by the identified SolarWinds parent processes.
* Conduct a thorough review of the affected system’s logs and configurations to identify any unauthorized changes or additional indicators of compromise.
* Restore the system from a known good backup if any unauthorized changes or malicious activities are confirmed.
* Update and patch the SolarWinds software and any other vulnerable applications on the affected system to mitigate known vulnerabilities.
* Implement application whitelisting to prevent unauthorized execution of command-line interpreters from SolarWinds processes.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to assess the potential impact on the broader network.


## Rule query [_rule_query_5786]

```js
process where host.os.type == "windows" and event.type == "start" and process.name: ("cmd.exe", "powershell.exe") and
process.parent.name: (
     "ConfigurationWizard*.exe",
     "NetflowDatabaseMaintenance*.exe",
     "NetFlowService*.exe",
     "SolarWinds.Administration*.exe",
     "SolarWinds.Collector.Service*.exe",
     "SolarwindsDiagnostics*.exe"
     )
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

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Supply Chain Compromise
    * ID: T1195
    * Reference URL: [https://attack.mitre.org/techniques/T1195/](https://attack.mitre.org/techniques/T1195/)

* Sub-technique:

    * Name: Compromise Software Supply Chain
    * ID: T1195.002
    * Reference URL: [https://attack.mitre.org/techniques/T1195/002/](https://attack.mitre.org/techniques/T1195/002/)



