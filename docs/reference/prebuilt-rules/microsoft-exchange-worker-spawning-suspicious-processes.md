---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-exchange-worker-spawning-suspicious-processes.html
---

# Microsoft Exchange Worker Spawning Suspicious Processes [microsoft-exchange-worker-spawning-suspicious-processes]

Identifies suspicious processes being spawned by the Microsoft Exchange Server worker process (w3wp). This activity may indicate exploitation activity or access to an existing web shell backdoor.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers)
* [https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities)
* [https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289](https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Initial Access
* Tactic: Execution
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 310

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_532]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft Exchange Worker Spawning Suspicious Processes**

Microsoft Exchange Server uses the worker process (w3wp.exe) to handle web requests, often running under specific application pools. Adversaries exploit this by executing malicious scripts or commands, potentially via web shells, to gain unauthorized access or execute arbitrary code. The detection rule identifies unusual child processes like command-line interpreters spawned by w3wp.exe, signaling possible exploitation or backdoor activity.

**Possible investigation steps**

* Review the alert details to confirm the parent process is w3wp.exe and check if the process arguments include "MSExchange*AppPool" to ensure the alert is relevant to Microsoft Exchange.
* Examine the child process details, focusing on the process names and original file names such as cmd.exe, powershell.exe, pwsh.exe, and powershell_ise.exe, to identify any unauthorized or unexpected command-line activity.
* Investigate the timeline of events leading up to the alert, including any preceding or subsequent processes, to understand the context and potential impact of the suspicious activity.
* Check for any associated network activity or connections initiated by the suspicious processes to identify potential data exfiltration or communication with external command and control servers.
* Review recent changes or access logs on the affected Exchange server to identify any unauthorized access attempts or modifications that could indicate exploitation or the presence of a web shell.
* Correlate the alert with other security events or logs from data sources like Elastic Endgame, Elastic Defend, Sysmon, Microsoft Defender for Endpoint, or SentinelOne to gather additional context and corroborate findings.
* Assess the risk and impact of the detected activity, considering the severity and risk score, and determine appropriate response actions, such as isolating the affected system or conducting a deeper forensic analysis.

**False positive analysis**

* Routine administrative tasks may trigger the rule if administrators use command-line tools like cmd.exe or powershell.exe for legitimate maintenance. To manage this, create exceptions for known administrative accounts or specific IP addresses that regularly perform these tasks.
* Scheduled tasks or scripts that run under the MSExchangeAppPool context might spawn command-line interpreters as part of their normal operation. Identify these tasks and exclude them by specifying their unique process arguments or command lines.
* Monitoring or backup software that interacts with Exchange Server could inadvertently trigger the rule. Review the software’s documentation to confirm its behavior and exclude its processes by name or hash if they are verified as safe.
* Custom applications or integrations that interact with Exchange Server and use command-line tools for automation may also cause false positives. Work with application developers to understand these interactions and exclude them based on process names or specific command-line patterns.
* If a known security tool or script is used to test Exchange Server’s security posture, it might mimic suspicious behavior. Document these tools and exclude their processes during scheduled testing periods to avoid false alerts.

**Response and remediation**

* Immediately isolate the affected Microsoft Exchange Server from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious processes identified as being spawned by w3wp.exe, such as cmd.exe or powershell.exe, to halt any ongoing malicious activity.
* Conduct a thorough review of the server’s application pools and web directories to identify and remove any unauthorized web shells or scripts.
* Restore the server from a known good backup taken before the suspicious activity was detected to ensure system integrity.
* Apply the latest security patches and updates to the Microsoft Exchange Server to mitigate known vulnerabilities and prevent exploitation.
* Monitor network traffic and server logs for any signs of continued or attempted exploitation, focusing on unusual outbound connections or repeated access attempts.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems have been compromised.


## Rule query [_rule_query_572]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "w3wp.exe" and process.parent.args : "MSExchange*AppPool" and
  (process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe") or
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



