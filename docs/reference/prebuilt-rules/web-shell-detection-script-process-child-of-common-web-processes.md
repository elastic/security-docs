---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/web-shell-detection-script-process-child-of-common-web-processes.html
---

# Web Shell Detection: Script Process Child of Common Web Processes [web-shell-detection-script-process-child-of-common-web-processes]

Identifies suspicious commands executed via a web server, which may suggest a vulnerability and remote shell access.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* logs-sentinel_one_cloud_funnel.*
* logs-m365_defender.event-*
* logs-crowdstrike.fdr*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.microsoft.com/security/blog/2020/02/04/ghost-in-the-shell-investigating-web-shell-attacks/](https://www.microsoft.com/security/blog/2020/02/04/ghost-in-the-shell-investigating-web-shell-attacks/)
* [https://www.elastic.co/security-labs/elastic-response-to-the-the-spring4shell-vulnerability-cve-2022-22965](https://www.elastic.co/security-labs/elastic-response-to-the-the-spring4shell-vulnerability-cve-2022-22965)
* [https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1](https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Persistence
* Tactic: Initial Access
* Tactic: Execution
* Resources: Investigation Guide
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: Crowdstrike

**Version**: 416

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1193]

**Triage and analysis**

**Investigating Web Shell Detection: Script Process Child of Common Web Processes**

Adversaries may backdoor web servers with web shells to establish persistent access to systems. A web shell is a web script that is placed on an openly accessible web server to allow an adversary to use the web server as a gateway into a network. A web shell may provide a set of functions to execute or a command-line interface on the system that hosts the web server.

This rule detects a web server process spawning script and command-line interface programs, potentially indicating attackers executing commands using the web shell.

**Possible investigation steps**

* Investigate abnormal behaviors observed by the subject process such as network connections, registry or file modifications, and any other spawned child processes.
* Examine the command line to determine which commands or scripts were executed.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences across hosts.
* If scripts or executables were dropped, retrieve the files and determine if they are malicious:
* Use a private sandboxed malware analysis system to perform analysis.
* Observe and collect information about the following activities:
* Attempts to contact external domains and addresses.
* File and registry access, modification, and creation activities.
* Service creation and launch activities.
* Scheduled task creation.
* Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
* Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

**False positive analysis**

* This activity is unlikely to happen legitimately. Any activity that triggered the alert and is not inherently malicious must be monitored by the security team.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* If the triage identified malware, search the environment for additional compromised hosts.
* Implement temporary network rules, procedures, and segmentation to contain the malware.
* Stop suspicious processes.
* Immediately block the identified indicators of compromise (IoCs).
* Inspect the affected systems for additional malware backdoors like reverse shells, reverse proxies, or droppers that attackers could use to reinfect the system.
* Remove and block malicious artifacts identified during triage.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_1219]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("w3wp.exe", "httpd.exe", "nginx.exe", "php.exe", "php-cgi.exe", "tomcat.exe") and
  process.name : ("cmd.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wmic.exe", "wscript.exe") and
  not
  (
    process.parent.name : ("php.exe", "httpd.exe") and process.name : "cmd.exe" and
    process.command_line : (
      "cmd.exe /c mode CON",
      "cmd.exe /s /c \"mode CON\"",
      "cmd.exe /c \"mode\"",
      "cmd.exe /s /c \"tput colors 2>&1\""
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Server Software Component
    * ID: T1505
    * Reference URL: [https://attack.mitre.org/techniques/T1505/](https://attack.mitre.org/techniques/T1505/)

* Sub-technique:

    * Name: Web Shell
    * ID: T1505.003
    * Reference URL: [https://attack.mitre.org/techniques/T1505/003/](https://attack.mitre.org/techniques/T1505/003/)

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

* Sub-technique:

    * Name: Visual Basic
    * ID: T1059.005
    * Reference URL: [https://attack.mitre.org/techniques/T1059/005/](https://attack.mitre.org/techniques/T1059/005/)

* Technique:

    * Name: Windows Management Instrumentation
    * ID: T1047
    * Reference URL: [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)



