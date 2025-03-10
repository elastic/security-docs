---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/microsoft-365-potential-ransomware-activity.html
---

# Microsoft 365 Potential ransomware activity [microsoft-365-potential-ransomware-activity]

Identifies when Microsoft Cloud App Security reports that a user has uploaded files to the cloud that might be infected with ransomware.

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

## Investigation guide [_investigation_guide_519]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Microsoft 365 Potential ransomware activity**

Microsoft 365’s cloud services can be exploited by adversaries to distribute ransomware by uploading infected files. This detection rule leverages Microsoft Cloud App Security to identify suspicious uploads, focusing on successful events flagged as potential ransomware activity. By monitoring specific event datasets and actions, it helps security analysts pinpoint and mitigate ransomware threats, aligning with MITRE ATT&CK’s impact tactics.

**Possible investigation steps**

* Review the event details in the Microsoft Cloud App Security console to confirm the specific files and user involved in the "Potential ransomware activity" alert.
* Check the event.dataset field for o365.audit logs to gather additional context about the user’s recent activities and any other related events.
* Investigate the event.provider field to ensure the alert originated from the SecurityComplianceCenter, confirming the source of the detection.
* Analyze the event.category field to verify that the activity is categorized as web, which may indicate the method of file upload.
* Assess the user’s recent activity history and permissions to determine if the upload was intentional or potentially malicious.
* Contact the user to verify the legitimacy of the uploaded files and gather any additional context or explanations for the activity.
* If the files are confirmed or suspected to be malicious, initiate a response plan to contain and remediate any potential ransomware threat, including isolating affected systems and notifying relevant stakeholders.

**False positive analysis**

* Legitimate file uploads by trusted users may trigger alerts if the files are mistakenly flagged as ransomware. To manage this, create exceptions for specific users or groups who frequently upload large volumes of files.
* Automated backup processes that upload encrypted files to the cloud can be misidentified as ransomware activity. Exclude these processes by identifying and whitelisting the associated service accounts or IP addresses.
* Certain file types or extensions commonly used in business operations might be flagged. Review and adjust the detection rule to exclude these file types if they are consistently identified as false positives.
* Collaborative tools that sync files across devices may cause multiple uploads that appear suspicious. Monitor and exclude these tools by recognizing their typical behavior patterns and adjusting the rule settings accordingly.
* Regularly review and update the list of exceptions to ensure that only verified non-threatening activities are excluded, maintaining the balance between security and operational efficiency.

**Response and remediation**

* Immediately isolate the affected user account to prevent further uploads and potential spread of ransomware within the cloud environment.
* Quarantine the uploaded files flagged as potential ransomware to prevent access and further distribution.
* Conduct a thorough scan of the affected user’s devices and cloud storage for additional signs of ransomware or other malicious activity.
* Notify the security operations team to initiate a deeper investigation into the source and scope of the ransomware activity, leveraging MITRE ATT&CK techniques for guidance.
* Restore any affected files from secure backups, ensuring that the backups are clean and free from ransomware.
* Review and update access controls and permissions for the affected user and related accounts to minimize the risk of future incidents.
* Escalate the incident to senior security management and, if necessary, involve legal or compliance teams to assess any regulatory implications.


## Setup [_setup_342]

The Office 365 Logs Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_558]

```js
event.dataset:o365.audit and event.provider:SecurityComplianceCenter and event.category:web and event.action:"Potential ransomware activity" and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Encrypted for Impact
    * ID: T1486
    * Reference URL: [https://attack.mitre.org/techniques/T1486/](https://attack.mitre.org/techniques/T1486/)



