---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-windows-command-shell-arguments.html
---

# Suspicious Windows Command Shell Arguments [prebuilt-rule-8-17-4-suspicious-windows-command-shell-arguments]

Identifies the execution of the Windows Command Shell process (cmd.exe) with suspicious argument values. This behavior is often observed during malware installation.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*
* logs-system.security*
* logs-windows.sysmon_operational-*
* logs-sentinel_one_cloud_funnel.*
* logs-m365_defender.event-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Execution
* Data Source: System
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Microsoft Defender for Endpoint
* Resources: Investigation Guide

**Version**: 202

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4860]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious Windows Command Shell Arguments**

The Windows Command Shell (cmd.exe) is a critical component for executing commands and scripts. Adversaries exploit it to execute malicious scripts, download payloads, or manipulate system settings. The detection rule identifies unusual command-line arguments and patterns indicative of such abuse, filtering out known benign processes to minimize false positives. This helps in early detection of potential threats by monitoring for suspicious command executions.

**Possible investigation steps**

* Review the command line arguments associated with the cmd.exe process to identify any suspicious patterns or keywords such as "curl", "regsvr32", "wscript", or "Invoke-WebRequest" that may indicate malicious activity.
* Check the parent process of the cmd.exe execution to determine if it is a known benign process or if it is associated with potentially malicious activity, especially if the parent process is explorer.exe or other unusual executables.
* Investigate the user account associated with the cmd.exe process to determine if the activity aligns with the user’s typical behavior or if it appears anomalous.
* Examine the network activity of the host to identify any unusual outbound connections or data transfers that may correlate with the suspicious command execution.
* Cross-reference the alert with other security logs or alerts from tools like Sysmon, SentinelOne, or Microsoft Defender for Endpoint to gather additional context and corroborate findings.
* Assess the risk score and severity of the alert to prioritize the investigation and determine if immediate response actions are necessary.

**False positive analysis**

* Processes related to Spiceworks and wmiprvse.exe can trigger false positives. Exclude these by adding exceptions for process arguments containing "%TEMP%\\Spiceworks\\*" when the parent process is wmiprvse.exe.
* Development tools like Perl, Node.js, and NetBeans may cause false alerts. Exclude these by specifying their executable paths in the exception list.
* Citrix Secure Access Client initiated by userinit.exe can be a false positive. Exclude this by adding an exception for process arguments containing "?:\\Program Files\\Citrix\\Secure Access Client\\nsauto.exe" with the parent process name as userinit.exe.
* Scheduled tasks or services like PCPitstopScheduleService.exe may trigger alerts. Exclude these by adding their paths to the exception list.
* Command-line operations involving npm or Maven commands can be benign. Exclude these by specifying command-line patterns like "\"cmd\" /c %NETBEANS_MAVEN_COMMAND_LINE%" in the exception list.

**Response and remediation**

* Isolate the affected system from the network to prevent further spread of potential malware or unauthorized access.
* Terminate any suspicious cmd.exe processes identified by the detection rule to halt malicious activity.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any malicious files or scripts.
* Review and restore any altered system settings or configurations to their original state to ensure system integrity.
* Analyze the command-line arguments and parent processes involved in the alert to understand the scope and origin of the threat, and identify any additional compromised systems.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional containment measures are necessary.
* Implement additional monitoring and detection rules to identify similar suspicious command-line activities in the future, enhancing the organization’s ability to detect and respond to such threats promptly.


## Rule query [_rule_query_5815]

```js
process where host.os.type == "windows" and event.type == "start" and
 process.name : "cmd.exe" and
 (

  process.command_line : ("*).Run(*", "*GetObject*", "* curl*regsvr32*", "*echo*wscript*", "*echo*ZONE.identifier*",
  "*ActiveXObject*", "*dir /s /b *echo*", "*unescape(*",  "*findstr*TVNDRgAAAA*", "*findstr*passw*", "*start*\\\\*\\DavWWWRoot\\*",
  "* explorer*%CD%*", "*%cd%\\*.js*", "*attrib*%CD%*", "*/?cMD<*", "*/AutoIt3ExecuteScript*..*", "*&cls&cls&cls&cls&cls&*",
  "*&#*;&#*;&#*;&#*;*", "* &&s^eT*", "*& ChrW(*", "*&explorer /root*", "*start __ & __\\*", "*findstr /V /L *forfiles*",
  "*=wscri& set *", "*http*!COmpUternaME!*", "*start *.pdf * start /min cmd.exe /c *\\\\*", "*pip install*System.Net.WebClient*",
  "*Invoke-WebReques*Start-Process*", "*-command (Invoke-webrequest*", "*copy /b *\\\\* ping *-n*", "*echo*.ToCharArray*") or

  (process.args : "echo" and process.parent.name : ("wscript.exe", "mshta.exe")) or

  process.args : ("1>?:\\*.vbs", "1>?:\\*.js") or

  (process.args : "explorer.exe" and process.args : "type" and process.args : ">" and process.args : "start") or

  (process.parent.name : "explorer.exe" and
   process.command_line :
           ("*&&S^eT *",
            "*&& set *&& set *&& set *&& set *&& set *&& call*",
            "**\\u00??\\u00??\\u00??\\u00??\\u00??\\u00??\\u00??\\u00??*")) or

   (process.parent.name : "explorer.exe" and process.args : "copy" and process.args : "&&" and process.args : "\\\\*@*\\*")
  ) and

  /* false positives */
  not (process.args : "%TEMP%\\Spiceworks\\*" and process.parent.name : "wmiprvse.exe") and
  not process.parent.executable :
                ("?:\\Perl64\\bin\\perl.exe",
                 "?:\\Program Files\\nodejs\\node.exe",
                 "?:\\Program Files\\HP\\RS\\pgsql\\bin\\pg_dumpall.exe",
                 "?:\\Program Files (x86)\\PRTG Network Monitor\\64 bit\\PRTG Server.exe",
                 "?:\\Program Files (x86)\\Spiceworks\\bin\\spiceworks-finder.exe",
                 "?:\\Program Files (x86)\\Zuercher Suite\\production\\leds\\leds.exe",
                 "?:\\Program Files\\Tripwire\\Agent\\Plugins\\twexec\\twexec.exe",
                 "D:\\Agents\\?\\_work\\_tasks\\*\\SonarScanner.MSBuild.exe",
                 "?:\\Program Files\\Microsoft VS Code\\Code.exe",
                 "?:\\programmiweb\\NetBeans-*\\netbeans\\bin\\netbeans64.exe",
                 "?:\\Program Files (x86)\\Public Safety Suite Professional\\production\\leds\\leds.exe",
                 "?:\\Program Files (x86)\\Tier2Tickets\\button_gui.exe",
                 "?:\\Program Files\\NetBeans-*\\netbeans\\bin\\netbeans*.exe",
                 "?:\\Program Files (x86)\\Public Safety Suite Professional\\production\\leds\\leds.exe",
                 "?:\\Program Files (x86)\\Tier2Tickets\\button_gui.exe",
                 "?:\\Program Files (x86)\\Helpdesk Button\\button_gui.exe",
                 "?:\\VTSPortable\\VTS\\jre\\bin\\javaw.exe",
                 "?:\\Program Files\\Bot Framework Composer\\Bot Framework Composer.exe",
                 "?:\\Program Files\\KMSYS Worldwide\\eQuate\\*\\SessionMgr.exe",
                 "?:\\Program Files (x86)\\Craneware\\Pricing Analyzer\\Craneware.Pricing.Shell.exe",
                 "?:\\Program Files (x86)\\jumpcloud-agent-app\\jumpcloud-agent-app.exe",
                 "?:\\Program Files\\PostgreSQL\\*\\bin\\pg_dumpall.exe",
                 "?:\\Program Files (x86)\\Vim\\vim*\\vimrun.exe") and
  not (process.args :  "?:\\Program Files\\Citrix\\Secure Access Client\\nsauto.exe" and process.parent.name : "userinit.exe") and
  not process.args :
            ("?:\\Program Files (x86)\\PCMatic\\PCPitstopScheduleService.exe",
             "?:\\Program Files (x86)\\AllesTechnologyAgent\\*",
             "https://auth.axis.com/oauth2/oauth-authorize*") and
  not process.command_line :
               ("\"cmd\" /c %NETBEANS_MAVEN_COMMAND_LINE%",
                "?:\\Windows\\system32\\cmd.exe /q /d /s /c \"npm.cmd ^\"install^\" ^\"--no-bin-links^\" ^\"--production^\"\"") and
  not (process.name : "cmd.exe" and process.args : "%TEMP%\\Spiceworks\\*" and process.args : "http*/dataloader/persist_netstat_data") and
  not (process.args == "echo" and process.args == "GEQ" and process.args == "1073741824")
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

    * Name: Windows Command Shell
    * ID: T1059.003
    * Reference URL: [https://attack.mitre.org/techniques/T1059/003/](https://attack.mitre.org/techniques/T1059/003/)



