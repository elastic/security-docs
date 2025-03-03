---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-suspicious-printspooler-service-executable-file-creation.html
---

# Suspicious PrintSpooler Service Executable File Creation [prebuilt-rule-8-17-4-suspicious-printspooler-service-executable-file-creation]

Detects attempts to exploit privilege escalation vulnerabilities related to the Print Spooler service. For more information refer to the following CVE’s - CVE-2020-1048, CVE-2020-1337 and CVE-2020-1300 and verify that the impacted system is patched.

**Rule type**: new_terms

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.file-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-m365_defender.event-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://voidsec.com/cve-2020-1337-printdemon-is-dead-long-live-printdemon/](https://voidsec.com/cve-2020-1337-printdemon-is-dead-long-live-printdemon/)
* [https://www.thezdi.com/blog/2020/7/8/cve-2020-1300-remote-code-execution-through-microsoft-windows-cab-files](https://www.thezdi.com/blog/2020/7/8/cve-2020-1300-remote-code-execution-through-microsoft-windows-cab-files)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: Elastic Endgame
* Use Case: Vulnerability
* Data Source: Elastic Defend
* Data Source: Sysmon
* Data Source: Microsoft Defender for Endpoint
* Data Source: SentinelOne
* Resources: Investigation Guide

**Version**: 315

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4970]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Suspicious PrintSpooler Service Executable File Creation**

The Print Spooler service in Windows manages print jobs, but vulnerabilities like CVE-2020-1048 can be exploited for privilege escalation. Adversaries may create malicious DLL files executed by the spooler to gain elevated privileges. The detection rule identifies such threats by monitoring file creation events linked to the spooler process, focusing on DLL files, which are common vectors for exploitation.

**Possible investigation steps**

* Review the alert details to confirm the presence of a file creation event with the extension "dll" associated with the "spoolsv.exe" process on a Windows host.
* Check the file path and name of the created DLL to determine if it matches known malicious patterns or locations typically used for exploitation.
* Investigate the source of the spoolsv.exe process by examining the parent process and any associated user accounts to identify potential unauthorized access or activity.
* Analyze recent system logs and security events for any other suspicious activities or anomalies around the time of the DLL creation, such as unexpected user logins or privilege changes.
* Verify the patch status of the affected system against the vulnerabilities CVE-2020-1048, CVE-2020-1337, and CVE-2020-1300 to ensure it is up to date and not susceptible to known exploits.
* If the DLL is confirmed to be malicious, isolate the affected system to prevent further exploitation and begin remediation efforts, including removing the malicious file and any associated threats.

**False positive analysis**

* Legitimate DLL updates by trusted software can trigger the rule. Users should verify the source of the DLL and, if confirmed safe, add the software’s update process to an exception list.
* System maintenance activities, such as Windows updates, may create DLLs that match the rule’s criteria. Users can exclude these activities by identifying the associated update processes and adding them to the exception list.
* Custom in-house applications that interact with the Print Spooler service might generate DLLs during normal operation. Users should validate these applications and exclude their file creation events if they are deemed non-threatening.
* Security software or monitoring tools that interact with the Print Spooler service could inadvertently create DLLs. Users should confirm the legitimacy of these tools and configure exceptions for their operations.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further exploitation or lateral movement by the adversary.
* Terminate the spoolsv.exe process if it is confirmed to be executing a malicious DLL, to halt any ongoing malicious activity.
* Remove the malicious DLL file from the system to prevent re-execution and further exploitation.
* Apply the latest security patches and updates to the affected system, specifically addressing CVE-2020-1048, CVE-2020-1337, and CVE-2020-1300, to close the vulnerabilities exploited by the adversary.
* Conduct a thorough review of user accounts and privileges on the affected system to ensure no unauthorized privilege escalation has occurred.
* Monitor the network for any signs of similar exploitation attempts or related suspicious activity, using enhanced logging and alerting mechanisms.
* Report the incident to the appropriate internal security team or external authorities if required, providing details of the exploit and actions taken for further investigation and response.


## Rule query [_rule_query_5925]

```js
event.category : "file" and host.os.type : "windows" and event.type : "creation" and
  process.name : "spoolsv.exe" and file.extension : "dll"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



