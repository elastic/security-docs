---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-build-engine-started-by-a-script-process.html
---

# Microsoft Build Engine Started by a Script Process [microsoft-build-engine-started-by-a-script-process]

An instance of MSBuild, the Microsoft Build Engine, was started by a script or the Windows command interpreter. This behavior is unusual and is sometimes used by malicious payloads.

**Rule type**: new_terms

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.*

**Severity**: low

**Risk score**: 21

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
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 312

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_526]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft Build Engine Started by a Script Process**

The Microsoft Build Engine (MSBuild) is a platform for building applications, typically invoked by developers. However, adversaries exploit its ability to execute inline tasks, using it as a proxy for executing malicious code. The detection rule identifies unusual MSBuild invocations initiated by script interpreters, signaling potential misuse for stealthy execution or defense evasion tactics.

**Possible investigation steps**

* Review the process tree to understand the parent-child relationship, focusing on the parent process names such as cmd.exe, powershell.exe, pwsh.exe, powershell_ise.exe, cscript.exe, wscript.exe, or mshta.exe, which initiated the msbuild.exe process.
* Examine the command line arguments used to start msbuild.exe to identify any suspicious or unusual inline tasks or scripts that may indicate malicious activity.
* Check the user account associated with the msbuild.exe process to determine if it aligns with expected usage patterns or if it might be compromised.
* Investigate the timing and frequency of the msbuild.exe execution to see if it coincides with known legitimate build activities or if it appears anomalous.
* Look for any related network activity or file modifications around the time of the msbuild.exe execution to identify potential data exfiltration or further malicious actions.
* Cross-reference the alert with other security events or logs to identify any correlated indicators of compromise or additional suspicious behavior.

**False positive analysis**

* Development environments where scripts are used to automate builds may trigger this rule. To manage this, identify and whitelist specific script processes or directories commonly used by developers.
* Automated testing frameworks that utilize scripts to initiate builds can cause false positives. Exclude these processes by creating exceptions for known testing tools and their associated scripts.
* Continuous integration/continuous deployment (CI/CD) pipelines often use scripts to invoke MSBuild. Consider excluding the parent processes associated with these pipelines from the rule.
* Administrative scripts that perform legitimate system maintenance tasks might start MSBuild. Review and exclude these scripts if they are verified as non-threatening.
* Custom scripts developed in-house for specific business functions may also trigger alerts. Conduct a review of these scripts and exclude them if they are deemed safe and necessary for operations.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate the suspicious MSBuild process and any associated script interpreter processes (e.g., cmd.exe, powershell.exe) to stop the execution of potentially malicious code.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious payloads or artifacts.
* Review and analyze the parent script or command that initiated the MSBuild process to understand the scope and intent of the attack, and identify any additional compromised systems or accounts.
* Reset credentials for any user accounts that were active on the affected system during the time of the alert to prevent unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for MSBuild and script interpreter activities across the network to detect and respond to similar threats in the future.


## Setup [_setup_349]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_565]

```js
host.os.type:windows and event.category:process and event.type:start and (
  process.name.caseless:"msbuild.exe" or process.pe.original_file_name:"MSBuild.exe") and
  process.parent.name:("cmd.exe" or "powershell.exe" or "pwsh.exe" or "powershell_ise.exe" or "cscript.exe" or
    "wscript.exe" or "mshta.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Trusted Developer Utilities Proxy Execution
    * ID: T1127
    * Reference URL: [https://attack.mitre.org/techniques/T1127/](https://attack.mitre.org/techniques/T1127/)

* Sub-technique:

    * Name: MSBuild
    * ID: T1127.001
    * Reference URL: [https://attack.mitre.org/techniques/T1127/001/](https://attack.mitre.org/techniques/T1127/001/)

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



