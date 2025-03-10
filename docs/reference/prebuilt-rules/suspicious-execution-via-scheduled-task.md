---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-execution-via-scheduled-task.html
---

# Suspicious Execution via Scheduled Task [suspicious-execution-via-scheduled-task]

Identifies execution of a suspicious program via scheduled tasks by looking at process lineage and command line usage.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper](https://www.elastic.co/security-labs/elastic-protects-against-data-wiper-malware-targeting-ukraine-hermeticwiper)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_986]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Execution via Scheduled Task**

Scheduled tasks in Windows automate routine tasks, but adversaries exploit them for persistence and execution of malicious programs. By examining process lineage and command line usage, the detection rule identifies suspicious executions initiated by scheduled tasks. It flags known malicious executables and unusual file paths, while excluding benign processes, to pinpoint potential threats effectively.

**Possible investigation steps**

* Review the process lineage to confirm the parent process is "svchost.exe" with arguments containing "Schedule" to verify the execution was initiated by a scheduled task.
* Examine the command line arguments and file paths of the suspicious process to identify any unusual or unauthorized file locations, such as those listed in the query (e.g., "C:\Users*", "C:\ProgramData\*").
* Check the original file name of the process against the list of known suspicious executables (e.g., "PowerShell.EXE", "Cmd.Exe") to determine if it matches any commonly abused binaries.
* Investigate the user context under which the process was executed, especially if it deviates from expected system accounts or known service accounts.
* Correlate the event with other security logs or alerts to identify any related suspicious activities or patterns that might indicate a broader attack campaign.
* Assess the risk and impact of the detected activity by considering the severity and risk score provided, and determine if immediate containment or remediation actions are necessary.

**False positive analysis**

* Scheduled tasks running legitimate scripts or executables like cmd.exe or cscript.exe in system directories may trigger false positives. To manage this, create exceptions for these processes when they are executed from known safe directories such as C:\Windows\System32.
* PowerShell scripts executed by the system account (S-1-5-18) for administrative tasks can be mistakenly flagged. Exclude these by specifying exceptions for PowerShell executions with arguments like -File or -PSConsoleFile when run by the system account.
* Legitimate software installations or updates using msiexec.exe by the system account may be incorrectly identified as threats. Mitigate this by excluding msiexec.exe processes initiated by the system account.
* Regular maintenance tasks or scripts stored in common directories like C:\ProgramData or C:\Windows\Temp might be flagged. Review these tasks and exclude known benign scripts or executables from these paths.
* Custom scripts or administrative tools that mimic suspicious executables (e.g., PowerShell.EXE, RUNDLL32.EXE) but are part of routine operations should be reviewed and excluded if verified as safe.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread of any potential malicious activity.
* Terminate any suspicious processes identified by the detection rule, especially those matching the flagged executables and paths.
* Conduct a thorough review of scheduled tasks on the affected system to identify and disable any unauthorized or suspicious tasks.
* Remove any malicious files or executables found in the suspicious paths listed in the detection rule.
* Restore the system from a known good backup if malicious activity is confirmed and system integrity is compromised.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for scheduled tasks and the flagged executables to detect similar threats in the future.


## Setup [_setup_626]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_1035]

```js
process where host.os.type == "windows" and event.type == "start" and
    /* Schedule service cmdline on Win10+ */
    process.parent.name : "svchost.exe" and process.parent.args : "Schedule" and
    /* add suspicious programs here */
    process.pe.original_file_name in
                                (
                                  "cscript.exe",
                                  "wscript.exe",
                                  "PowerShell.EXE",
                                  "Cmd.Exe",
                                  "MSHTA.EXE",
                                  "RUNDLL32.EXE",
                                  "REGSVR32.EXE",
                                  "MSBuild.exe",
                                  "InstallUtil.exe",
                                  "RegAsm.exe",
                                  "RegSvcs.exe",
                                  "msxsl.exe",
                                  "CONTROL.EXE",
                                  "EXPLORER.EXE",
                                  "Microsoft.Workflow.Compiler.exe",
                                  "msiexec.exe"
                                  ) and
    /* add suspicious paths here */
    process.args : (
       "C:\\Users\\*",
       "C:\\ProgramData\\*",
       "C:\\Windows\\Temp\\*",
       "C:\\Windows\\Tasks\\*",
       "C:\\PerfLogs\\*",
       "C:\\Intel\\*",
       "C:\\Windows\\Debug\\*",
       "C:\\HP\\*") and

     not (process.name : "cmd.exe" and process.args : "?:\\*.bat" and process.working_directory : "?:\\Windows\\System32\\") and
     not (process.name : "cscript.exe" and process.args : "?:\\Windows\\system32\\calluxxprovider.vbs") and
     not (process.name : "powershell.exe" and process.args : ("-File", "-PSConsoleFile") and user.id : "S-1-5-18") and
     not (process.name : "msiexec.exe" and user.id : "S-1-5-18")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Scheduled Task
    * ID: T1053.005
    * Reference URL: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Scheduled Task
    * ID: T1053.005
    * Reference URL: [https://attack.mitre.org/techniques/T1053/005/](https://attack.mitre.org/techniques/T1053/005/)



