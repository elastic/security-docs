---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/windows-script-interpreter-executing-process-via-wmi.html
---

# Windows Script Interpreter Executing Process via WMI [windows-script-interpreter-executing-process-via-wmi]

Identifies use of the built-in Windows script interpreters (cscript.exe or wscript.exe) being used to execute a process via Windows Management Instrumentation (WMI). This may be indicative of malicious activity.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-endpoint.events.library-*
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
* Tactic: Initial Access
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Resources: Investigation Guide

**Version**: 211

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1206]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Windows Script Interpreter Executing Process via WMI**

Windows Management Instrumentation (WMI) is a powerful Windows feature that allows for system management and automation. Adversaries exploit WMI to execute scripts or processes stealthily, often using script interpreters like cscript.exe or wscript.exe. The detection rule identifies suspicious activity by monitoring for these interpreters executing processes via WMI, especially when initiated by non-system accounts, indicating potential malicious intent.

**Possible investigation steps**

* Review the alert details to identify the specific script interpreter (cscript.exe or wscript.exe) and the process it executed. Check the process name and executable path for any anomalies or known malicious indicators.
* Examine the user account associated with the process execution. Verify if the user domain is not "NT AUTHORITY" and assess whether the account is expected to perform such actions. Investigate any unusual or unauthorized account activity.
* Investigate the parent process wmiprvse.exe to determine how it was initiated. Look for any preceding suspicious activities or processes that might have triggered the WMI execution.
* Check the system for any additional indicators of compromise, such as unexpected network connections, changes in system configurations, or other alerts related to the same host or user.
* Correlate the event with other security logs and alerts to identify any patterns or related incidents that might indicate a broader attack campaign or persistent threat.

**False positive analysis**

* Legitimate administrative scripts or automation tasks may trigger this rule if they use cscript.exe or wscript.exe via WMI. To handle this, identify and document these scripts, then create exceptions for their specific execution paths or user accounts.
* Software installations or updates that utilize script interpreters through WMI can be mistaken for malicious activity. Monitor and whitelist known installation processes or update mechanisms that are frequently used in your environment.
* Custom applications or internal tools that rely on WMI for process execution might be flagged. Review these applications and exclude their specific process names or executable paths from the rule.
* Scheduled tasks or system maintenance scripts executed by non-system accounts could generate alerts. Verify these tasks and exclude them by specifying the user accounts or domains that are authorized to perform such actions.
* Security tools or monitoring solutions that leverage WMI for legitimate purposes may also be detected. Identify these tools and add them to the exception list based on their process names or executable locations.

**Response and remediation**

* Immediately isolate the affected host from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes identified in the alert, such as cscript.exe or wscript.exe, that are running under non-system accounts.
* Conduct a thorough review of the affected host’s scheduled tasks, startup items, and services to identify and remove any persistence mechanisms.
* Analyze the parent process wmiprvse.exe and its command-line arguments to understand the scope of the attack and identify any additional compromised systems.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if the threat is part of a larger campaign.
* Implement additional monitoring and alerting for similar activities across the network, focusing on WMI-based script execution and non-standard process launches.
* Review and update endpoint protection policies to block or alert on the execution of high-risk processes like those listed in the detection query, especially when initiated by non-system accounts.


## Rule query [_rule_query_1234]

```js
sequence by host.id with maxspan = 5s
    [any where host.os.type == "windows" and
     (event.category : ("library", "driver") or (event.category == "process" and event.action : "Image loaded*")) and
     (?dll.name : "wmiutils.dll" or file.name : "wmiutils.dll") and process.name : ("wscript.exe", "cscript.exe")]
    [process where host.os.type == "windows" and event.type == "start" and
     process.parent.name : "wmiprvse.exe" and
     user.domain != "NT AUTHORITY" and
     (process.pe.original_file_name :
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
        ) or
      process.executable : ("C:\\Users\\*.exe", "C:\\ProgramData\\*.exe")
     )
    ]
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

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Windows Management Instrumentation
    * ID: T1047
    * Reference URL: [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: Visual Basic
    * ID: T1059.005
    * Reference URL: [https://attack.mitre.org/techniques/T1059/005/](https://attack.mitre.org/techniques/T1059/005/)



