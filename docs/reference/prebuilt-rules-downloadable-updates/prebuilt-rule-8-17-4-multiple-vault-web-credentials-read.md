---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-multiple-vault-web-credentials-read.html
---

# Multiple Vault Web Credentials Read [prebuilt-rule-8-17-4-multiple-vault-web-credentials-read]

Windows Credential Manager allows you to create, view, or delete saved credentials for signing into websites, connected applications, and networks. An adversary may abuse this to list or dump credentials stored in the Credential Manager for saved usernames and passwords. This may also be performed in preparation of lateral movement.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5382](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5382)
* [https://www.elastic.co/security-labs/detect-credential-access](https://www.elastic.co/security-labs/detect-credential-access)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: System
* Resources: Investigation Guide

**Version**: 112

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4732]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Multiple Vault Web Credentials Read**

Windows Credential Manager stores credentials for web logins, apps, and networks, facilitating seamless user access. Adversaries exploit this by extracting stored credentials, potentially aiding lateral movement within networks. The detection rule identifies suspicious activity by flagging consecutive credential reads from the same process, excluding benign actions like localhost access, thus highlighting potential credential dumping attempts.

**Possible investigation steps**

* Review the process associated with the flagged PID to determine if it is a legitimate application or potentially malicious. Check for known software or unusual executables.
* Investigate the source and destination of the web credentials read by examining the winlog.event_data.Resource field to identify any suspicious or unexpected URLs.
* Check the winlog.computer_name to identify the affected system and assess whether it is a high-value target or has been involved in previous suspicious activities.
* Analyze the timeline of events around the alert to identify any preceding or subsequent suspicious activities that may indicate a broader attack pattern.
* Verify the user context by examining the winlog.event_data.SubjectLogonId to ensure the activity was not performed by a privileged or administrative account without proper authorization.
* Cross-reference the event with other security logs or alerts to identify any correlated activities that might suggest a coordinated attack or compromise.

**False positive analysis**

* Localhost access is a common false positive since the rule excludes localhost reads. Ensure that any legitimate applications accessing credentials via localhost are properly whitelisted to prevent unnecessary alerts.
* Automated scripts or applications that frequently access web credentials for legitimate purposes may trigger the rule. Identify these processes and create exceptions for them to reduce noise.
* System maintenance or updates might involve credential reads that are benign. Coordinate with IT teams to schedule these activities and temporarily adjust the rule sensitivity or add exceptions during these periods.
* Security tools or monitoring software that perform regular checks on credential integrity could be flagged. Verify these tools and add them to an exception list if they are part of the organization’s security infrastructure.
* User behavior such as frequent password changes or credential updates might cause alerts. Educate users on the impact of their actions and consider adjusting the rule to accommodate expected behavior patterns.

**Response and remediation**

* Isolate the affected system from the network to prevent potential lateral movement by the adversary.
* Terminate the suspicious process identified by the process ID (pid) involved in the credential reads to stop further credential access.
* Conduct a thorough review of the affected system for any additional signs of compromise, such as unauthorized user accounts or scheduled tasks.
* Change passwords for any accounts that may have been exposed, focusing on those stored in the Windows Credential Manager.
* Implement network segmentation to limit access to critical systems and data, reducing the risk of lateral movement.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the scope of the breach.
* Enhance monitoring and logging on the affected system and similar endpoints to detect any future attempts at credential dumping or unauthorized access.


## Setup [_setup_1519]

**Setup**

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_5687]

```js
sequence by winlog.computer_name, winlog.process.pid with maxspan=1s

 /* 2 consecutive vault reads from same pid for web creds */

 [any where event.code : "5382" and
  (winlog.event_data.SchemaFriendlyName : "Windows Web Password Credential" and winlog.event_data.Resource : "http*") and
  not winlog.event_data.SubjectLogonId : "0x3e7" and
  not winlog.event_data.Resource : "http://localhost/"]

 [any where event.code : "5382" and
  (winlog.event_data.SchemaFriendlyName : "Windows Web Password Credential" and winlog.event_data.Resource : "http*") and
  not winlog.event_data.SubjectLogonId : "0x3e7" and
  not winlog.event_data.Resource : "http://localhost/"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Technique:

    * Name: Credentials from Password Stores
    * ID: T1555
    * Reference URL: [https://attack.mitre.org/techniques/T1555/](https://attack.mitre.org/techniques/T1555/)

* Sub-technique:

    * Name: Windows Credential Manager
    * ID: T1555.004
    * Reference URL: [https://attack.mitre.org/techniques/T1555/004/](https://attack.mitre.org/techniques/T1555/004/)



