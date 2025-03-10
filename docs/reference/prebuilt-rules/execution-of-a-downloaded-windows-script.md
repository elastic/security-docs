---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/execution-of-a-downloaded-windows-script.html
---

# Execution of a Downloaded Windows Script [execution-of-a-downloaded-windows-script]

Identifies the creation of a Windows script downloaded from the internet followed by the execution of a scripting utility. Adversaries may use Windows script files for initial access and execution.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

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
* Tactic: Execution
* Data Source: Elastic Defend
* Resources: Investigation Guide

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_314]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Execution of a downloaded windows script**

Windows scripts, often used for legitimate automation tasks, can be exploited by adversaries to execute malicious code. Attackers may download scripts via browsers or file utilities, then execute them using scripting tools like wscript or mshta. The detection rule identifies such threats by monitoring script creation from internet sources and subsequent execution, focusing on unusual parent-child process relationships and script attributes.

**Possible investigation steps**

* Review the file creation event to identify the specific script file that was downloaded, noting its name, path, and extension to understand the potential threat.
* Examine the origin URL or referrer URL of the downloaded script to determine the source and assess its legitimacy or potential malicious intent.
* Investigate the parent process, such as chrome.exe or explorer.exe, to understand how the script was downloaded and whether it aligns with typical user behavior.
* Analyze the execution event of the scripting utility (wscript.exe or mshta.exe) to identify the command-line arguments used, which may provide insight into the script’s intended actions.
* Check the user account associated with the script execution to determine if the activity is expected for that user or if it indicates a compromised account.
* Correlate the timing of the script creation and execution events to see if they fall within a suspicious timeframe, such as outside of normal working hours.
* Look for any additional related alerts or logs on the host that might indicate further malicious activity or lateral movement following the script execution.

**False positive analysis**

* Legitimate script automation tools may trigger this rule if they download and execute scripts from the internet. Users can create exceptions for known safe tools by excluding specific file paths or process names.
* Software updates or installations that download scripts as part of their process might be flagged. To handle this, users can whitelist specific origin URLs or referrer URLs associated with trusted software vendors.
* Internal scripts distributed via corporate intranet sites could be misidentified as threats. Users should consider excluding scripts with known internal origin URLs or specific user IDs associated with IT operations.
* Browser extensions or plugins that automate tasks using scripts may cause false positives. Users can exclude these by identifying and excluding the specific browser process names or file extensions involved.
* Frequent use of file utilities like winrar or 7zFM for legitimate script handling can be excluded by specifying trusted file paths or user IDs that regularly perform these actions.

**Response and remediation**

* Isolate the affected system from the network to prevent further execution of potentially malicious scripts and lateral movement.
* Terminate any suspicious processes identified in the alert, such as wscript.exe or mshta.exe, to stop the execution of the downloaded script.
* Quarantine the downloaded script file and any associated files to prevent further execution and facilitate forensic analysis.
* Conduct a thorough scan of the affected system using updated antivirus or endpoint detection and response (EDR) tools to identify and remove any additional malicious files or remnants.
* Review and analyze the origin URL and referrer URL of the downloaded script to identify potential malicious websites or compromised sources, and block these URLs at the network level.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are affected.
* Implement application whitelisting to restrict the execution of unauthorized scripts and scripting utilities, reducing the risk of similar threats in the future.


## Rule query [_rule_query_329]

```js
sequence by host.id, user.id with maxspan=3m
[file where host.os.type == "windows" and event.action == "creation" and user.id != "S-1-5-18" and
  process.name : ("chrome.exe", "msedge.exe", "brave.exe", "browser.exe", "dragon.exe", "vivaldi.exe", "explorer.exe", "winrar.exe", "7zFM.exe", "7zG.exe", "Bandizip.exe") and
  file.extension in~ ("js", "jse", "vbs", "vbe", "wsh", "hta", "cmd", "bat") and
  (file.origin_url != null or file.origin_referrer_url != null)]
[process where host.os.type == "windows" and event.type == "start" and
 process.parent.name : "explorer.exe" and process.args_count >= 2 and
 (
  process.name in~ ("wscript.exe", "mshta.exe") or
  (process.name : "cmd.exe" and process.command_line : ("*.cmd*", "*.bat*"))
  )]
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

    * Name: Visual Basic
    * ID: T1059.005
    * Reference URL: [https://attack.mitre.org/techniques/T1059/005/](https://attack.mitre.org/techniques/T1059/005/)

* Sub-technique:

    * Name: JavaScript
    * ID: T1059.007
    * Reference URL: [https://attack.mitre.org/techniques/T1059/007/](https://attack.mitre.org/techniques/T1059/007/)

* Sub-technique:

    * Name: Windows Command Shell
    * ID: T1059.003
    * Reference URL: [https://attack.mitre.org/techniques/T1059/003/](https://attack.mitre.org/techniques/T1059/003/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Mshta
    * ID: T1218.005
    * Reference URL: [https://attack.mitre.org/techniques/T1218/005/](https://attack.mitre.org/techniques/T1218/005/)



