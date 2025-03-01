---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/suspicious-jetbrains-teamcity-child-process.html
---

# Suspicious JetBrains TeamCity Child Process [suspicious-jetbrains-teamcity-child-process]

Identifies suspicious processes being spawned by the JetBrain TeamCity process. This activity could be related to JetBrains remote code execution vulnerabilities.

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

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.trendmicro.com/en_us/research/24/c/teamcity-vulnerability-exploits-lead-to-jasmin-ransomware.html](https://www.trendmicro.com/en_us/research/24/c/teamcity-vulnerability-exploits-lead-to-jasmin-ransomware.md)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Initial Access
* Data Source: Elastic Endgame
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Data Source: Microsoft Defender for Endpoint
* Data Source: System
* Data Source: Sysmon
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 204

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_998]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious JetBrains TeamCity Child Process**

JetBrains TeamCity is a continuous integration and deployment server used to automate software development processes. Adversaries may exploit vulnerabilities in TeamCity to execute unauthorized code, potentially spawning malicious child processes. The detection rule identifies unusual child processes initiated by TeamCity’s Java executable, flagging potential exploitation attempts by monitoring for known suspicious executables, while excluding legitimate operations.

**Possible investigation steps**

* Review the process tree to identify the parent and child processes associated with the suspicious activity, focusing on the parent executable paths like "?:\TeamCity\jre\bin\java.exe".
* Examine the command-line arguments of the suspicious child processes, especially those involving "cmd.exe" or "powershell.exe", to understand the actions being executed.
* Check for any recent vulnerabilities or patches related to JetBrains TeamCity that might explain the suspicious behavior.
* Investigate the user account under which the suspicious processes were executed to determine if it aligns with expected usage patterns or if it indicates potential compromise.
* Correlate the alert with other security events or logs from data sources like Sysmon or Microsoft Defender for Endpoint to identify any related malicious activity or indicators of compromise.
* Assess network activity from the host to detect any unusual outbound connections that might suggest data exfiltration or communication with a command and control server.

**False positive analysis**

* Legitimate build scripts may invoke command-line utilities like cmd.exe or powershell.exe. To handle these, create exceptions for specific scripts by matching known safe arguments or paths.
* Automated tasks or maintenance scripts might use network utilities such as ping.exe or netstat.exe. Exclude these by identifying and allowing specific scheduled tasks or maintenance windows.
* System monitoring tools could trigger processes like tasklist.exe or systeminfo.exe. Whitelist these tools by verifying their source and ensuring they are part of authorized monitoring solutions.
* Development or testing environments may frequently use utilities like explorer.exe or control.exe. Establish exceptions for these environments by defining specific hostnames or IP ranges where such activity is expected.
* Custom scripts or applications might use msiexec.exe for legitimate software installations. Allow these by confirming the source and purpose of the installations, and excluding them based on known safe paths or signatures.

**Response and remediation**

* Immediately isolate the affected TeamCity server from the network to prevent further unauthorized access or lateral movement.
* Terminate any suspicious child processes identified by the detection rule, such as cmd.exe or powershell.exe, to halt potential malicious activities.
* Conduct a thorough review of recent changes and deployments in TeamCity to identify any unauthorized modifications or suspicious activities.
* Apply the latest security patches and updates to TeamCity and its underlying Java runtime environment to mitigate known vulnerabilities.
* Restore the affected system from a clean backup taken before the suspicious activity was detected, ensuring no remnants of the exploit remain.
* Monitor network traffic and system logs for any signs of continued or related suspicious activity, focusing on the indicators identified in the detection rule.
* Escalate the incident to the security operations center (SOC) or relevant IT security team for further investigation and to assess the need for additional security measures.


## Rule query [_rule_query_1047]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.parent.executable :
                 ("?:\\TeamCity\\jre\\bin\\java.exe",
                  "?:\\Program Files\\TeamCity\\jre\\bin\\java.exe",
                  "?:\\Program Files (x86)\\TeamCity\\jre\\bin\\java.exe",
                  "?:\\TeamCity\\BuildAgent\\jre\\bin\\java.exe") and
  process.name : ("cmd.exe", "powershell.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "curl.exe", "ssh.exe",
                   "rundll32.exe", "regsvr32.exe", "mshta.exe", "certreq.exe", "net.exe", "nltest.exe", "whoami.exe", "hostname.exe",
                   "tasklist.exe", "arp.exe", "nbtstat.exe", "netstat.exe", "reg.exe", "tasklist.exe", "Microsoft.Workflow.Compiler.exe",
                   "arp.exe", "atbroker.exe", "bginfo.exe", "bitsadmin.exe", "cdb.exe", "cmstp.exe", "control.exe", "cscript.exe", "csi.exe",
                   "dnx.exe", "dsget.exe", "dsquery.exe", "forfiles.exe", "fsi.exe", "ftp.exe", "gpresult.exe", "ieexec.exe", "iexpress.exe",
                   "installutil.exe", "ipconfig.exe","msxsl.exe", "netsh.exe", "odbcconf.exe", "ping.exe", "pwsh.exe", "qprocess.exe",
                   "quser.exe", "qwinsta.exe", "rcsi.exe", "regasm.exe", "regsvcs.exe", "regsvr32.exe", "sc.exe", "schtasks.exe",
                   "systeminfo.exe", "tracert.exe", "wmic.exe", "wscript.exe","xwizard.exe", "explorer.exe", "msdt.exe") and
 not (process.name : "powershell.exe" and process.args : "-ExecutionPolicy" and process.args : "?:\\TeamCity\\buildAgent\\work\\*.ps1") and
 not (process.name : "cmd.exe" and process.args : "dir" and process.args : "/-c")
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



