---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/iis-http-logging-disabled.html
---

# IIS HTTP Logging Disabled [iis-http-logging-disabled]

Identifies when Internet Information Services (IIS) HTTP Logging is disabled on a server. An attacker with IIS server access via a webshell or other mechanism can disable HTTP Logging as an effective anti-forensics measure.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.process-*
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

**Maximum alerts per execution**: 33

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Data Source: Elastic Endgame
* Resources: Investigation Guide
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike

**Version**: 312

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_419]

**Triage and analysis**

**Investigating IIS HTTP Logging Disabled**

IIS (Internet Information Services) is a Microsoft web server software used to host websites and web applications on Windows. It provides features for serving dynamic and static content, and can be managed through a graphical interface or command-line tools.

IIS logging is a data source that can be used for security monitoring, forensics, and incident response. It contains mainly information related to requests done to the web server, and can be used to spot malicious activities like webshells. Adversaries can tamper, clear, and delete this data to evade detection, cover their tracks, and slow down incident response.

This rule monitors commands that disable IIS logging.

**Possible investigation steps**

* Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Contact the account owner and confirm whether they are aware of this activity.
* Investigate other alerts associated with the user/host during the past 48 hours.
* Verify if any other anti-forensics behaviors were observed.
* Verify whether the logs stored in the `C:\inetpub\logs\logfiles\w3svc1` directory were deleted after this action.
* Check if this operation is done under change management and approved according to the organization’s policy.

**False positive analysis**

* This activity is unlikely to happen legitimately. Benign true positives (B-TPs) can be added as exceptions if necessary.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Isolate the involved host to prevent further post-compromise behavior.
* Re-enable affected logging components, services, and security monitoring.
* Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
* Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_451]

```js
process where host.os.type == "windows" and event.type == "start" and
  (process.name : "appcmd.exe" or ?process.pe.original_file_name == "appcmd.exe") and
  process.args : "/dontLog*:*True" and
  not process.parent.name : "iissetup.exe"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable Windows Event Logging
    * ID: T1562.002
    * Reference URL: [https://attack.mitre.org/techniques/T1562/002/](https://attack.mitre.org/techniques/T1562/002/)



