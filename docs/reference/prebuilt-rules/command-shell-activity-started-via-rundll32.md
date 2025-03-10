---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/command-shell-activity-started-via-rundll32.html
---

# Command Shell Activity Started via RunDLL32 [command-shell-activity-started-via-rundll32]

Identifies command shell activity started via RunDLL32, which is commonly abused by attackers to host malicious code.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

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
* Tactic: Execution
* Tactic: Credential Access
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 311

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_226]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Command Shell Activity Started via RunDLL32**

RunDLL32 is a legitimate Windows utility used to execute functions in DLLs, often leveraged by attackers to run malicious code stealthily. Adversaries exploit it to launch command shells like cmd.exe or PowerShell, bypassing security controls. The detection rule identifies such abuse by monitoring for command shells initiated by RunDLL32, excluding known benign patterns, thus highlighting potential threats.

**Possible investigation steps**

* Review the process details to confirm the parent-child relationship between rundll32.exe and the command shell (cmd.exe or powershell.exe) to ensure the alert is not a false positive.
* Examine the command line arguments of rundll32.exe to identify any suspicious or unusual DLLs or functions being executed, excluding known benign patterns.
* Check the user account associated with the process to determine if it aligns with expected behavior or if it indicates potential compromise.
* Investigate the source and destination network connections associated with the process to identify any suspicious or unauthorized communication.
* Correlate the event with other security alerts or logs from the same host or user to identify any patterns or additional indicators of compromise.
* Review recent changes or activities on the host, such as software installations or updates, that might explain the execution of rundll32.exe with command shells.

**False positive analysis**

* Known false positives include command shells initiated by RunDLL32 for legitimate administrative tasks or software installations.
* Exclude command lines that match common benign patterns, such as those involving SHELL32.dll or temporary files used by trusted applications.
* Regularly update the list of exceptions to include new benign patterns identified through monitoring and analysis.
* Collaborate with IT and security teams to identify and document legitimate use cases of RunDLL32 in your environment.
* Use process monitoring tools to verify the legitimacy of command shells started by RunDLL32, ensuring they align with expected behavior.

**Response and remediation**

* Isolate the affected system from the network to prevent further malicious activity and lateral movement.
* Terminate any suspicious processes identified as cmd.exe or powershell.exe that were initiated by rundll32.exe to halt potential malicious actions.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious files or remnants.
* Review and analyze the rundll32.exe command line arguments to understand the scope and intent of the activity, and identify any additional compromised systems or accounts.
* Reset credentials for any user accounts that were active on the affected system during the time of the alert to prevent unauthorized access.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for rundll32.exe and related processes to detect similar activities in the future and improve response times.


## Rule query [_rule_query_234]

```js
process where host.os.type == "windows" and event.type == "start" and
 process.name : ("cmd.exe", "powershell.exe") and
  process.parent.name : "rundll32.exe" and process.parent.command_line != null and
  /* common FPs can be added here */
  not process.parent.args : ("C:\\Windows\\System32\\SHELL32.dll,RunAsNewUser_RunDLL",
                             "C:\\WINDOWS\\*.tmp,zzzzInvokeManagedCustomActionOutOfProc")
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

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Rundll32
    * ID: T1218.011
    * Reference URL: [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)



