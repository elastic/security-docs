---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-screenconnect-server-spawning-suspicious-processes.html
---

# ScreenConnect Server Spawning Suspicious Processes [prebuilt-rule-8-17-4-screenconnect-server-spawning-suspicious-processes]

Identifies suspicious processes being spawned by the ScreenConnect server process (ScreenConnect.Service.exe). This activity may indicate exploitation activity or access to an existing web shell backdoor.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
* logs-windows.forwarded*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*
* logs-crowdstrike.fdr*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blackpointcyber.com/resources/blog/breaking-through-the-screen/](https://blackpointcyber.com/resources/blog/breaking-through-the-screen/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Initial Access
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 204

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4876]

**Triage and analysis**

[TBC: QUOTE]
**Investigating ScreenConnect Server Spawning Suspicious Processes**

ScreenConnect, a remote support tool, allows administrators to control systems remotely. Adversaries may exploit this by executing unauthorized commands or scripts, potentially using it as a backdoor. The detection rule identifies unusual child processes like command shells spawned by the ScreenConnect service, signaling possible exploitation or web shell activity, thus aiding in early threat detection.

**Possible investigation steps**

* Review the alert details to confirm the parent process is ScreenConnect.Service.exe and identify the suspicious child process name, such as cmd.exe or powershell.exe.
* Check the timestamp of the process start event to determine when the suspicious activity occurred and correlate it with any other unusual activities or alerts around the same time.
* Investigate the user account associated with the process to determine if it is a legitimate user or potentially compromised.
* Examine the command line arguments of the spawned process to identify any malicious or unauthorized commands being executed.
* Review network logs for any unusual outbound connections initiated by the ScreenConnect service or the suspicious child process, which may indicate data exfiltration or communication with a command and control server.
* Analyze the system for any additional indicators of compromise, such as unexpected file modifications or the presence of web shells, to assess the extent of the potential breach.

**False positive analysis**

* Legitimate administrative tasks using command shells or scripting tools like cmd.exe or powershell.exe may trigger the rule. To manage this, create exceptions for known administrative scripts or tasks that are regularly executed by trusted users.
* Automated maintenance scripts that utilize ScreenConnect for legitimate purposes can be mistaken for suspicious activity. Identify these scripts and whitelist their execution paths or specific process names to prevent false alerts.
* Software updates or installations that require command line execution through ScreenConnect might be flagged. Document these processes and exclude them from the rule by specifying the associated process names or hashes.
* Security tools or monitoring solutions that interact with ScreenConnect for legitimate scanning or logging purposes may inadvertently trigger the rule. Verify these tools and add them to an exception list based on their process identifiers or parent-child process relationships.
* Training or demonstration sessions using ScreenConnect to showcase command line features could be misinterpreted as threats. Schedule these sessions and temporarily adjust the rule sensitivity or disable it during the known timeframes to avoid false positives.

**Response and remediation**

* Isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified as being spawned by ScreenConnect.Service.exe, such as cmd.exe or powershell.exe, to halt any ongoing malicious activity.
* Conduct a thorough review of recent ScreenConnect session logs to identify unauthorized access or unusual activity patterns, and revoke any compromised credentials.
* Scan the affected system for additional indicators of compromise, such as web shells or other malware, using endpoint detection and response tools.
* Apply security patches and updates to the ScreenConnect server and any other vulnerable applications to mitigate exploitation risks.
* Restore the system from a known good backup if evidence of compromise is confirmed, ensuring that the backup is free from malicious artifacts.
* Report the incident to the appropriate internal security team or external authorities if required, providing them with detailed findings and evidence for further investigation.


## Rule query [_rule_query_5831]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "ScreenConnect.Service.exe" and
  (process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "csc.exe") or
  ?process.pe.original_file_name in ("cmd.exe", "powershell.exe", "pwsh.dll", "powershell_ise.exe"))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)

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



