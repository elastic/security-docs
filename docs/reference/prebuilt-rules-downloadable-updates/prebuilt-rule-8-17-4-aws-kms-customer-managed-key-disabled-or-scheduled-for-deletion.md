---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-kms-customer-managed-key-disabled-or-scheduled-for-deletion.html
---

# AWS KMS Customer Managed Key Disabled or Scheduled for Deletion [prebuilt-rule-8-17-4-aws-kms-customer-managed-key-disabled-or-scheduled-for-deletion]

Identifies attempts to disable or schedule the deletion of an AWS KMS Customer Managed Key (CMK). Deleting an AWS KMS key is destructive and potentially dangerous. It deletes the key material and all metadata associated with the KMS key and is irreversible. After a KMS key is deleted, the data that was encrypted under that KMS key can no longer be decrypted, which means that data becomes unrecoverable.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/cli/latest/reference/kms/disable-key.html](https://docs.aws.amazon.com/cli/latest/reference/kms/disable-key.md)
* [https://docs.aws.amazon.com/cli/latest/reference/kms/schedule-key-deletion.html](https://docs.aws.amazon.com/cli/latest/reference/kms/schedule-key-deletion.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS KMS
* Use Case: Log Auditing
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Xavier Pich

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4024]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS KMS Customer Managed Key Disabled or Scheduled for Deletion**

AWS Key Management Service (KMS) allows users to create and manage cryptographic keys for data encryption. Customer Managed Keys (CMKs) are crucial for securing sensitive data. Adversaries may disable or schedule deletion of CMKs to render encrypted data inaccessible, causing data loss. The detection rule monitors successful disablement or deletion attempts, alerting analysts to potential data destruction activities.

**Possible investigation steps**

* Review the CloudTrail logs for the specific event.dataset:aws.cloudtrail entries to identify the user or role that initiated the DisableKey or ScheduleKeyDeletion action.
* Check the event.provider:kms.amazonaws.com logs to gather additional context about the KMS key involved, including its key ID and any associated metadata.
* Investigate the event.action:("DisableKey" or "ScheduleKeyDeletion") to determine if the action was authorized and aligns with recent changes or requests within the organization.
* Analyze the event.outcome:success to confirm the success of the action and assess the potential impact on encrypted data.
* Cross-reference the timing of the event with any known incidents or maintenance activities to rule out false positives or expected behavior.
* Contact the user or team responsible for the action to verify the intent and ensure it was a legitimate operation.

**False positive analysis**

* Routine key management activities by authorized personnel can trigger alerts. Regularly review and document key management procedures to differentiate between legitimate and suspicious activities.
* Automated scripts or tools used for key rotation or lifecycle management might disable or schedule deletion of keys as part of their process. Identify and whitelist these scripts or tools to prevent unnecessary alerts.
* Testing environments where keys are frequently created and deleted for development purposes can generate false positives. Exclude these environments from monitoring or adjust the rule to focus on production environments.
* Scheduled maintenance or compliance audits may involve disabling keys temporarily. Coordinate with relevant teams to schedule these activities and temporarily adjust monitoring rules to avoid false alerts.
* Misconfigured alerts due to incorrect tagging or categorization of keys can lead to false positives. Ensure that all keys are correctly tagged and categorized to align with monitoring rules.

**Response and remediation**

* Immediately verify the legitimacy of the disablement or deletion action by contacting the key owner or relevant stakeholders to confirm if the action was intentional.
* If the action was unauthorized, revoke any access credentials or permissions associated with the user or service that performed the action to prevent further unauthorized activities.
* Restore access to encrypted data by identifying any backup keys or data recovery options available, and initiate data recovery procedures if possible.
* Escalate the incident to the security operations team and relevant management to assess the impact and coordinate a broader response if necessary.
* Implement additional monitoring and alerting for any further attempts to disable or delete KMS keys, ensuring that alerts are sent to the appropriate personnel for rapid response.
* Review and tighten IAM policies and permissions related to KMS key management to ensure that only authorized personnel have the ability to disable or delete keys.
* Conduct a post-incident review to identify any gaps in the current security posture and update incident response plans to address similar threats in the future.


## Setup [_setup_938]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5041]

```js
event.dataset:aws.cloudtrail and event.provider:kms.amazonaws.com and event.action:("DisableKey" or "ScheduleKeyDeletion") and event.outcome:success
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



