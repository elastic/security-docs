---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-microsoft-exchange-server-um-spawning-suspicious-processes.html
---

# Microsoft Exchange Server UM Spawning Suspicious Processes [prebuilt-rule-8-17-4-microsoft-exchange-server-um-spawning-suspicious-processes]

Identifies suspicious processes being spawned by the Microsoft Exchange Server Unified Messaging (UM) service. This activity has been observed exploiting CVE-2021-26857.

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

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers)
* [https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Initial Access
* Tactic: Lateral Movement
* Data Source: Elastic Endgame
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Data Source: System
* Data Source: Microsoft Defender for Endpoint
* Data Source: Sysmon
* Data Source: SentinelOne
* Data Source: Crowdstrike
* Resources: Investigation Guide

**Version**: 312

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4873]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft Exchange Server UM Spawning Suspicious Processes**

Microsoft Exchange Server’s Unified Messaging (UM) integrates voice messaging with email, allowing users to access voicemails via their inbox. Adversaries exploit vulnerabilities like CVE-2021-26857 to execute unauthorized processes, potentially leading to system compromise. The detection rule identifies unusual processes initiated by UM services, excluding known legitimate executables, to flag potential exploitation attempts.

**Possible investigation steps**

* Review the alert details to confirm the process parent name is either "UMService.exe" or "UMWorkerProcess.exe" and verify the process executable path is not among the known legitimate paths listed in the exclusion criteria.
* Gather additional context by checking the process command line arguments and the user account under which the suspicious process was executed to identify any anomalies or unauthorized access.
* Investigate the historical activity of the host by reviewing recent logs for any other unusual or unauthorized processes, especially those related to the Microsoft Exchange Server.
* Check for any recent patches or updates applied to the Microsoft Exchange Server to ensure that vulnerabilities like CVE-2021-26857 have been addressed.
* Correlate the alert with other security tools and data sources such as Microsoft Defender for Endpoint or Sysmon to identify any related suspicious activities or indicators of compromise.
* Assess the network activity from the host to detect any potential lateral movement or data exfiltration attempts that might be associated with the suspicious process.

**False positive analysis**

* Legitimate UM service updates or patches may trigger the rule. Regularly update the list of known legitimate executables to include new or updated UM service files.
* Custom scripts or monitoring tools that interact with UM services might be flagged. Identify these scripts and add their executables to the exclusion list if they are verified as safe.
* Non-standard installation paths for Exchange Server can cause false positives. Ensure that all legitimate installation paths are included in the exclusion list to prevent unnecessary alerts.
* Administrative tasks performed by IT staff using command-line tools may be misidentified. Document these tasks and consider excluding the associated executables if they are part of routine maintenance.
* Third-party integrations with Exchange Server that spawn processes could be flagged. Verify these integrations and exclude their executables if they are deemed secure and necessary for business operations.

**Response and remediation**

* Isolate the affected Microsoft Exchange Server from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified as being spawned by the UM service that are not part of the known legitimate executables list.
* Apply the latest security patches and updates to the Microsoft Exchange Server to address CVE-2021-26857 and any other known vulnerabilities.
* Conduct a thorough review of the server’s security logs and network traffic to identify any additional indicators of compromise or unauthorized access attempts.
* Restore the server from a known good backup taken before the suspicious activity was detected, ensuring that the backup is free from compromise.
* Implement enhanced monitoring and alerting for any future suspicious processes spawned by the UM service, using the detection rule as a baseline.
* Escalate the incident to the organization’s security operations center (SOC) or incident response team for further investigation and to determine if additional systems may be affected.


## Rule query [_rule_query_5828]

```js
process where host.os.type == "windows" and event.type == "start" and
  process.parent.name : ("UMService.exe", "UMWorkerProcess.exe") and
    not process.executable : (
          "?:\\Windows\\System32\\werfault.exe",
          "?:\\Windows\\System32\\wermgr.exe",
          "?:\\Program Files\\Microsoft\\Exchange Server\\V??\\Bin\\UMWorkerProcess.exe",
          "?:\\Program Files\\Microsoft\\Exchange Server\\Bin\\UMWorkerProcess.exe",
          "D:\\Exchange 2016\\Bin\\UMWorkerProcess.exe",
          "E:\\ExchangeServer\\Bin\\UMWorkerProcess.exe",
          "D:\\Exchange\\Bin\\UMWorkerProcess.exe",
          "D:\\Exchange Server\\Bin\\UMWorkerProcess.exe",
          "E:\\Exchange Server\\V15\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume?\\Windows\\System32\\werfault.exe",
          "\\Device\\HarddiskVolume?\\Windows\\System32\\wermgr.exe",
          "\\Device\\HarddiskVolume?\\Program Files\\Microsoft\\Exchange Server\\V??\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume?\\Program Files\\Microsoft\\Exchange Server\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume?\\Exchange 2016\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume?\\ExchangeServer\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume?\\Exchange\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume?\\Exchange Server\\Bin\\UMWorkerProcess.exe",
          "\\Device\\HarddiskVolume?\\Exchange Server\\V15\\Bin\\UMWorkerProcess.exe"
    )
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

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Exploitation of Remote Services
    * ID: T1210
    * Reference URL: [https://attack.mitre.org/techniques/T1210/](https://attack.mitre.org/techniques/T1210/)



