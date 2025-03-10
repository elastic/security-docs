---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-process-creation-via-secondary-logon.html
---

# Process Creation via Secondary Logon [prebuilt-rule-8-17-4-process-creation-via-secondary-logon]

Identifies process creation with alternate credentials. Adversaries may create a new process with a different token to escalate privileges and bypass access controls.

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

* [https://attack.mitre.org/techniques/T1134/002/](https://attack.mitre.org/techniques/T1134/002/)

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Privilege Escalation
* Data Source: System
* Resources: Investigation Guide

**Version**: 111

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4952]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Process Creation via Secondary Logon**

The Secondary Logon service in Windows allows users to run processes with different credentials, facilitating legitimate administrative tasks. However, adversaries can exploit this to escalate privileges by creating processes with alternate tokens, bypassing access controls. The detection rule identifies such abuse by monitoring successful logins via the Secondary Logon service and subsequent process creation, linking them through unique logon identifiers.

**Possible investigation steps**

* Review the event logs for the specific TargetLogonId to identify the user account associated with the process creation and verify if the account is authorized to use alternate credentials.
* Examine the source IP address "::1" to confirm if the process creation originated from the local machine, which might indicate a local privilege escalation attempt.
* Investigate the process name "svchost.exe" to determine if it is being used legitimately or if it has been exploited for malicious purposes, such as running unauthorized services.
* Check the sequence of events within the 1-minute maxspan to identify any unusual or suspicious activities that occurred immediately before or after the process creation.
* Correlate the detected activity with other security alerts or logs to identify any patterns or additional indicators of compromise that might suggest a broader attack campaign.

**False positive analysis**

* Legitimate administrative tasks using the Secondary Logon service can trigger alerts. To manage this, identify and whitelist specific administrative accounts or tasks that frequently use this service for legitimate purposes.
* Scheduled tasks or automated scripts that use alternate credentials for routine operations may cause false positives. Review and exclude these tasks by creating exceptions for known scripts or scheduled jobs.
* Internal IT support activities often involve using alternate credentials for troubleshooting or maintenance. Document and exclude these activities by maintaining a list of support personnel and their typical actions.
* Software updates or installations that require elevated privileges might be flagged. Monitor and exclude these processes by identifying and documenting the update mechanisms used within the organization.
* Development or testing environments where alternate credentials are used for testing purposes can generate alerts. Exclude these environments by setting up specific rules that recognize and ignore these non-production activities.

**Response and remediation**

* Immediately isolate the affected system from the network to prevent further unauthorized access or lateral movement by the adversary.
* Terminate any suspicious processes identified as being created via the Secondary Logon service, especially those linked to the unique logon identifiers from the alert.
* Review and revoke any alternate credentials or tokens used in the suspicious process creation to prevent further misuse.
* Conduct a thorough examination of the affected system for additional signs of compromise, such as unauthorized user accounts or changes to system configurations.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine the full scope of the breach.
* Implement stricter access controls and monitoring on the Secondary Logon service to detect and prevent similar privilege escalation attempts in the future.
* Update and reinforce endpoint detection and response (EDR) solutions to enhance monitoring of process creation events and logon activities, ensuring they are aligned with the latest threat intelligence.


## Setup [_setup_1558]

**Setup**

Audit events 4624 and 4688 are needed to trigger this rule.

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until version 8.2. Hence for this rule to work effectively, users will need to add a custom ingest pipeline to populate `event.ingested` to @timestamp. For more details on adding a custom ingest pipeline refer - [/docs-content/docs/reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md](docs-content://reference/ingestion-tools/fleet/data-streams-pipeline-tutorial.md)


## Rule query [_rule_query_5907]

```js
sequence by winlog.computer_name with maxspan=1m

[authentication where event.action:"logged-in" and
 event.outcome == "success" and user.id : ("S-1-5-21-*", "S-1-12-1-*") and

 /* seclogon service */
 process.name == "svchost.exe" and
 winlog.event_data.LogonProcessName : "seclogo*" and source.ip == "::1" ] by winlog.event_data.TargetLogonId

[process where event.type == "start"] by winlog.event_data.TargetLogonId
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Access Token Manipulation
    * ID: T1134
    * Reference URL: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)

* Sub-technique:

    * Name: Create Process with Token
    * ID: T1134.002
    * Reference URL: [https://attack.mitre.org/techniques/T1134/002/](https://attack.mitre.org/techniques/T1134/002/)

* Sub-technique:

    * Name: Make and Impersonate Token
    * ID: T1134.003
    * Reference URL: [https://attack.mitre.org/techniques/T1134/003/](https://attack.mitre.org/techniques/T1134/003/)



