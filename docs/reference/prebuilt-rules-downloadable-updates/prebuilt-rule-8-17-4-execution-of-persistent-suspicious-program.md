---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-execution-of-persistent-suspicious-program.html
---

# Execution of Persistent Suspicious Program [prebuilt-rule-8-17-4-execution-of-persistent-suspicious-program]

Identifies execution of suspicious persistent programs (scripts, rundll32, etc.) by looking at process lineage and command line usage.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*

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
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4926]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Execution of Persistent Suspicious Program**

Persistent programs, like scripts or rundll32, are often used by adversaries to maintain access to a system. These programs can be executed at startup, leveraging process lineage and command line arguments to evade detection. The detection rule identifies suspicious executions by monitoring the sequence of processes initiated after user logon, focusing on known malicious executables and unusual file paths, thus highlighting potential abuse of persistence mechanisms.

**Possible investigation steps**

* Review the process lineage to confirm the sequence of userinit.exe, explorer.exe, and the suspicious child process. Verify if the child process was indeed launched shortly after user logon.
* Examine the command line arguments of the suspicious process to identify any unusual or malicious patterns, especially those involving known suspicious paths like C:\Users*, C:\ProgramData\*, or C:\Windows\Temp\*.
* Check the original file name of the suspicious process against known malicious executables such as cscript.exe, wscript.exe, or PowerShell.EXE to determine if it matches any of these.
* Investigate the parent process explorer.exe to ensure it was not compromised or manipulated to launch the suspicious child process.
* Analyze the user account associated with the suspicious process to determine if it has been involved in any other suspicious activities or if it has elevated privileges that could be exploited.
* Review recent system changes or installations that might have introduced the suspicious executable or altered startup configurations.

**False positive analysis**

* Legitimate administrative scripts or tools may trigger alerts if they are executed from common directories like C:\Users or C:\ProgramData. To manage this, create exceptions for known administrative scripts that are regularly used in your environment.
* Software updates or installations might use processes like PowerShell or RUNDLL32, leading to false positives. Identify and exclude these processes when they are part of a verified update or installation routine.
* Custom scripts or automation tasks that run at startup could be flagged. Document these tasks and exclude them from the rule if they are part of normal operations.
* Security or monitoring tools that use similar execution patterns may be mistakenly identified. Verify these tools and add them to an exclusion list to prevent unnecessary alerts.
* User-initiated actions that mimic suspicious behavior, such as running scripts from the command line, can cause false positives. Educate users on safe practices and adjust the rule to exclude known benign user actions.

**Response and remediation**

* Isolate the affected host from the network to prevent further spread or communication with potential command and control servers.
* Terminate any suspicious processes identified in the alert, such as those executed by cscript.exe, wscript.exe, PowerShell.EXE, MSHTA.EXE, RUNDLL32.EXE, REGSVR32.EXE, RegAsm.exe, MSBuild.exe, or InstallUtil.exe.
* Remove any unauthorized or suspicious startup entries or scheduled tasks that may have been created to ensure persistence.
* Conduct a thorough scan of the system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or remnants.
* Review and restore any modified system configurations or registry settings to their default or secure state.
* Escalate the incident to the security operations center (SOC) or incident response team for further analysis and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for the affected host and similar systems to detect any recurrence or related suspicious activities.


## Rule query [_rule_query_5881]

```js
/* userinit followed by explorer followed by early child process of explorer (unlikely to be launched interactively) within 1m */
sequence by host.id, user.name with maxspan=1m
  [process where host.os.type == "windows" and event.type == "start" and process.name : "userinit.exe" and process.parent.name : "winlogon.exe"]
  [process where host.os.type == "windows" and event.type == "start" and process.name : "explorer.exe"]
  [process where host.os.type == "windows" and event.type == "start" and process.parent.name : "explorer.exe" and
   /* add suspicious programs here */
   process.pe.original_file_name in ("cscript.exe",
                                     "wscript.exe",
                                     "PowerShell.EXE",
                                     "MSHTA.EXE",
                                     "RUNDLL32.EXE",
                                     "REGSVR32.EXE",
                                     "RegAsm.exe",
                                     "MSBuild.exe",
                                     "InstallUtil.exe") and
    /* add potential suspicious paths here */
    process.args : ("C:\\Users\\*", "C:\\ProgramData\\*", "C:\\Windows\\Temp\\*", "C:\\Windows\\Tasks\\*", "C:\\PerfLogs\\*", "C:\\Intel\\*")
   ]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Sub-technique:

    * Name: Registry Run Keys / Startup Folder
    * ID: T1547.001
    * Reference URL: [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)



