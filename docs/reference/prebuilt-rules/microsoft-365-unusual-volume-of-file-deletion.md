---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-365-unusual-volume-of-file-deletion.html
---

# Microsoft 365 Unusual Volume of File Deletion [microsoft-365-unusual-volume-of-file-deletion]

Identifies that a user has deleted an unusually large volume of files as reported by Microsoft Cloud App Security.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-o365*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy](https://docs.microsoft.com/en-us/cloud-app-security/anomaly-detection-policy)
* [https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference](https://docs.microsoft.com/en-us/cloud-app-security/policy-template-reference)

**Tags**:

* Domain: Cloud
* Data Source: Microsoft 365
* Use Case: Configuration Audit
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_523]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Unusual Volume of File Deletion**

Microsoft 365’s cloud environment facilitates file storage and collaboration, but its vast data handling capabilities can be exploited by adversaries for data destruction. Attackers may delete large volumes of files to disrupt operations or cover their tracks. The detection rule leverages audit logs to identify anomalies in file deletion activities, flagging successful, unusual deletion volumes as potential security incidents, thus enabling timely investigation and response.

**Possible investigation steps**

* Review the audit logs for the specific user associated with the alert to confirm the volume and context of the file deletions, focusing on entries with event.action:"Unusual volume of file deletion" and event.outcome:success.
* Correlate the timestamps of the deletion events with other activities in the user’s account to identify any suspicious patterns or anomalies, such as unusual login locations or times.
* Check for any recent changes in user permissions or roles that might explain the ability to delete a large volume of files, ensuring these align with the user’s typical responsibilities.
* Investigate any recent security alerts or incidents involving the same user or related accounts to determine if this activity is part of a broader attack or compromise.
* Contact the user or their manager to verify if the deletions were intentional and authorized, and gather any additional context that might explain the activity.
* Assess the impact of the deletions on business operations and data integrity, and determine if any recovery actions are necessary to restore critical files.

**False positive analysis**

* High-volume legitimate deletions during data migration or cleanup projects can trigger false positives. To manage this, create exceptions for users or groups involved in these activities during the specified time frame.
* Automated processes or scripts that perform bulk deletions as part of routine maintenance may be flagged. Identify these processes and whitelist them to prevent unnecessary alerts.
* Users with roles in data management or IT support may regularly delete large volumes of files as part of their job responsibilities. Establish a baseline for these users and adjust the detection thresholds accordingly.
* Temporary spikes in file deletions due to organizational changes, such as department restructuring, can be mistaken for malicious activity. Monitor these events and temporarily adjust the rule parameters to accommodate expected changes.
* Regularly review and update the list of exceptions to ensure that only legitimate activities are excluded from alerts, maintaining the effectiveness of the detection rule.

**Response and remediation**

* Immediately isolate the affected user account to prevent further unauthorized file deletions. This can be done by disabling the account or changing the password.
* Review the audit logs to identify the scope of the deletion and determine if any critical or sensitive files were affected. Restore these files from backups if available.
* Conduct a thorough review of the affected user’s recent activities to identify any other suspicious actions or potential indicators of compromise.
* Escalate the incident to the security operations team for further investigation and to determine if the deletion is part of a larger attack or breach.
* Implement additional monitoring on the affected account and similar high-risk accounts to detect any further unusual activities.
* Review and update access controls and permissions to ensure that users have the minimum necessary access to perform their job functions, reducing the risk of large-scale deletions.
* Coordinate with the IT and security teams to conduct a post-incident review, identifying any gaps in the response process and implementing improvements to prevent recurrence.


## Setup [_setup_346]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_562]

```js
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"Unusual volume of file deletion" and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Destruction
    * ID: T1485
    * Reference URL: [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)



