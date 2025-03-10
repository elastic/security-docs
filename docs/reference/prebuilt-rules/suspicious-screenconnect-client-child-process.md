---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-screenconnect-client-child-process.html
---

# Suspicious ScreenConnect Client Child Process [suspicious-screenconnect-client-child-process]

Identifies suspicious processes being spawned by the ScreenConnect client processes. This activity may indicate execution abusing unauthorized access to the ScreenConnect remote access software.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* logs-system.security*
* endgame-*
* logs-sentinel_one_cloud_funnel.*
* logs-m365_defender.event-*
* logs-crowdstrike.fdr*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708](https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Command and Control
* Resources: Investigation Guide
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Microsoft Defender for Endpoint
* Data Source: System
* Data Source: Crowdstrike

**Version**: 308

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1030]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious ScreenConnect Client Child Process**

ScreenConnect, a remote access tool, facilitates legitimate remote support but can be exploited by adversaries to execute unauthorized commands. Malicious actors may spawn processes like PowerShell or cmd.exe via ScreenConnect to perform harmful activities. The detection rule identifies such suspicious child processes, focusing on unusual arguments and process names, indicating potential abuse of remote access capabilities.

**Possible investigation steps**

* Review the parent process name to confirm it is one of the ScreenConnect client processes listed in the query, such as ScreenConnect.ClientService.exe or ScreenConnect.WindowsClient.exe, to verify the source of the suspicious activity.
* Examine the child process name and arguments, such as powershell.exe with encoded commands or cmd.exe with /c, to identify potentially malicious actions or commands being executed.
* Check the network activity associated with the suspicious process, especially if the process arguments include network-related terms like **http** or **downloadstring**, to determine if there is any unauthorized data exfiltration or command and control communication.
* Investigate the user account under which the suspicious process was executed to assess if the account has been compromised or is being misused.
* Correlate the event with other security alerts or logs from data sources like Elastic Defend or Microsoft Defender for Endpoint to gather additional context and identify any related malicious activities.
* Review the system’s recent activity and changes, such as new scheduled tasks or services created by schtasks.exe or sc.exe, to identify any persistence mechanisms that may have been established by the attacker.

**False positive analysis**

* Legitimate IT support activities using ScreenConnect may trigger the rule when executing scripts or commands for maintenance. To manage this, identify and whitelist specific IT support accounts or IP addresses that regularly perform these actions.
* Automated scripts or scheduled tasks that use ScreenConnect for routine operations might be flagged. Review and document these scripts, then create exceptions for known benign processes and arguments.
* Software updates or installations initiated through ScreenConnect can appear suspicious. Maintain a list of approved software and update processes, and exclude these from the rule.
* Internal security tools or monitoring solutions that leverage ScreenConnect for legitimate purposes may be detected. Verify these tools and add them to an exclusion list to prevent false positives.
* Training sessions or demonstrations using ScreenConnect to showcase command-line tools could be misinterpreted as threats. Ensure these sessions are logged and recognized as non-threatening, and adjust the rule to accommodate these scenarios.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the attacker.
* Terminate any suspicious processes identified in the alert, such as PowerShell, cmd.exe, or other flagged executables, to halt any ongoing malicious activity.
* Review and revoke any unauthorized user accounts or privileges that may have been created or modified using tools like net.exe or schtasks.exe.
* Conduct a thorough scan of the affected system using endpoint protection tools to identify and remove any malware or unauthorized software installed by the attacker.
* Restore the system from a known good backup if any critical system files or configurations have been altered or compromised.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement enhanced monitoring and logging for ScreenConnect and other remote access tools to detect similar activities in the future, ensuring that alerts are promptly reviewed and acted upon.


## Rule query [_rule_query_1081]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name :
                ("ScreenConnect.ClientService.exe",
                 "ScreenConnect.WindowsClient.exe",
                 "ScreenConnect.WindowsBackstageShell.exe",
                 "ScreenConnect.WindowsFileManager.exe") and
  (
   (process.name : "powershell.exe" and
    process.args : ("-enc", "-ec", "-e", "*downloadstring*", "*Reflection.Assembly*", "*http*")) or
   (process.name : "cmd.exe" and process.args : "/c") or
   (process.name : "net.exe" and process.args : "/add") or
   (process.name : "schtasks.exe" and process.args : ("/create", "-create")) or
   (process.name : "sc.exe" and process.args : "create") or
   (process.name : "rundll32.exe" and not process.args : "url.dll,FileProtocolHandler") or
   (process.name : "msiexec.exe" and process.args : ("/i", "-i") and
    process.args : ("/q", "/quiet", "/qn", "-q", "-quiet", "-qn", "-Q+")) or
   process.name : ("mshta.exe", "certutil.exe", "bistadmin.exe", "certreq.exe", "wscript.exe", "cscript.exe", "curl.exe",
                   "ssh.exe", "scp.exe", "wevtutil.exe", "wget.exe", "wmic.exe")
   )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Remote Access Software
    * ID: T1219
    * Reference URL: [https://attack.mitre.org/techniques/T1219/](https://attack.mitre.org/techniques/T1219/)



