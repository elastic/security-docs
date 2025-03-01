---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/unusual-service-host-child-process-childless-service.html
---

# Unusual Service Host Child Process - Childless Service [unusual-service-host-child-process-childless-service]

Identifies unusual child processes of Service Host (svchost.exe) that traditionally do not spawn any child processes. This may indicate a code injection or an equivalent form of exploitation.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* winlogbeat-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

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
* Tactic: Defense Evasion
* Tactic: Privilege Escalation
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

## Investigation guide [_investigation_guide_1156]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Unusual Service Host Child Process - Childless Service**

Service Host (svchost.exe) is a critical Windows process that hosts multiple services to optimize resource usage. Typically, certain services under svchost.exe do not spawn child processes. Adversaries exploit this by injecting malicious code to execute unauthorized processes, evading detection. The detection rule identifies anomalies by monitoring child processes of traditionally childless services, flagging potential exploitation attempts.

**Possible investigation steps**

* Review the process details of the child process, including its name and executable path, to determine if it is a known legitimate process or potentially malicious.
* Examine the parent process arguments to confirm if the svchost.exe instance is associated with a service that traditionally does not spawn child processes, as listed in the query.
* Check the process creation time and correlate it with any other suspicious activities or alerts in the system around the same timeframe.
* Investigate the user account under which the child process was executed to assess if it has the necessary privileges and if the activity aligns with typical user behavior.
* Analyze any network connections or file modifications made by the child process to identify potential malicious actions or data exfiltration attempts.
* Cross-reference the child process with known false positives listed in the query to rule out benign activities.
* Utilize threat intelligence sources to determine if the child process or its executable path is associated with known malware or attack patterns.

**False positive analysis**

* Processes like WerFault.exe, WerFaultSecure.exe, and wermgr.exe are known to be legitimate Windows error reporting tools that may occasionally be spawned by svchost.exe. To handle these, add them to the exclusion list in the detection rule to prevent unnecessary alerts.
* RelPost.exe associated with WdiSystemHost can be a legitimate process in certain environments. If this is a common occurrence, consider adding an exception for this executable when it is spawned by WdiSystemHost.
* Rundll32.exe executing winethc.dll with ForceProxyDetectionOnNextRun arguments under WdiServiceHost may be a benign operation in some network configurations. If verified as non-malicious, exclude this specific process and argument combination.
* Processes under the imgsvc service, such as lexexe.exe from Kodak directories, might be legitimate in environments using specific imaging software. Validate these occurrences and exclude them if they are confirmed to be non-threatening.
* Regularly review and update the exclusion list to ensure it reflects the current environment and does not inadvertently allow malicious activity.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further spread or communication with potential command and control servers.
* Terminate any suspicious child processes spawned by svchost.exe that are not typically associated with legitimate operations, as identified in the alert.
* Conduct a thorough scan of the affected system using updated antivirus and anti-malware tools to identify and remove any injected malicious code or associated malware.
* Review and analyze the process tree and parent-child relationships to understand the scope of the compromise and identify any additional affected processes or systems.
* Restore the affected system from a known good backup if malicious activity is confirmed and cannot be fully remediated through cleaning.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional systems are compromised.
* Implement enhanced monitoring and logging for svchost.exe and related processes to detect similar anomalies in the future, ensuring that alerts are configured to notify the appropriate personnel promptly.


## Rule query [_rule_query_1192]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : "svchost.exe" and

  /* based on svchost service arguments -s svcname where the service is known to be childless */
  process.parent.args : (
    "WdiSystemHost", "LicenseManager", "StorSvc", "CDPSvc", "cdbhsvc", "BthAvctpSvc", "SstpSvc", "WdiServiceHost",
    "imgsvc", "TrkWks", "WpnService", "IKEEXT", "PolicyAgent", "CryptSvc", "netprofm", "ProfSvc", "StateRepository",
    "camsvc", "LanmanWorkstation", "NlaSvc", "EventLog", "hidserv", "DisplayEnhancementService", "ShellHWDetection",
    "AppHostSvc", "fhsvc", "CscService", "PushToInstall"
  ) and

  /* unknown FPs can be added here */
  not process.name : ("WerFault.exe", "WerFaultSecure.exe", "wermgr.exe") and
  not (process.executable : "?:\\Windows\\System32\\RelPost.exe" and process.parent.args : "WdiSystemHost") and
  not (
    process.name : "rundll32.exe" and
    process.args : "?:\\WINDOWS\\System32\\winethc.dll,ForceProxyDetectionOnNextRun" and
    process.parent.args : "WdiServiceHost"
  ) and
  not (
    process.executable : (
      "?:\\Program Files\\*",
      "?:\\Program Files (x86)\\*",
      "?:\\Windows\\System32\\Kodak\\kds_?????\\lib\\lexexe.exe"
    ) and process.parent.args : "imgsvc"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Sub-technique:

    * Name: Process Hollowing
    * ID: T1055.012
    * Reference URL: [https://attack.mitre.org/techniques/T1055/012/](https://attack.mitre.org/techniques/T1055/012/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Sub-technique:

    * Name: Process Hollowing
    * ID: T1055.012
    * Reference URL: [https://attack.mitre.org/techniques/T1055/012/](https://attack.mitre.org/techniques/T1055/012/)



