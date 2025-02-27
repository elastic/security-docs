---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-rds-snapshot-export.html
---

# AWS RDS Snapshot Export [prebuilt-rule-8-17-4-aws-rds-snapshot-export]

Identifies the export of an Amazon Relational Database Service (RDS) Aurora database snapshot.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StartExportTask.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_StartExportTask.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Use Case: Asset Visibility
* Tactic: Exfiltration
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4015]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS RDS Snapshot Export**

Amazon RDS Snapshot Export allows users to export Aurora database snapshots to Amazon S3, facilitating data analysis and backup. However, adversaries may exploit this feature to exfiltrate sensitive data by exporting snapshots without authorization. The detection rule monitors successful export tasks in AWS CloudTrail logs, flagging potential misuse by identifying unexpected or unauthorized snapshot exports.

**Possible investigation steps**

* Review the AWS CloudTrail logs for the specific event.action:StartExportTask to identify the user or role that initiated the export task.
* Check the event.provider:rds.amazonaws.com logs to verify the source IP address and location from which the export task was initiated, looking for any anomalies or unexpected locations.
* Investigate the event.dataset:aws.cloudtrail logs to determine the specific database snapshot that was exported and assess its sensitivity or criticality.
* Cross-reference the event.outcome:success with IAM policies and permissions to ensure the user or role had legitimate access to perform the export task.
* Analyze any recent changes in IAM roles or policies that might have inadvertently granted export permissions to unauthorized users.
* Contact the data owner or relevant stakeholders to confirm whether the export task was authorized and aligns with business needs.

**False positive analysis**

* Routine data exports for legitimate business purposes may trigger alerts. Users should review export tasks to confirm they align with expected business operations and consider whitelisting known, authorized export activities.
* Automated backup processes that regularly export snapshots to S3 can be mistaken for unauthorized actions. Identify and document these processes, then create exceptions in the monitoring system to prevent false alerts.
* Development and testing environments often involve frequent snapshot exports for testing purposes. Ensure these environments are clearly identified and excluded from alerts by setting up specific rules or tags that differentiate them from production environments.
* Exports initiated by third-party services or integrations that have been granted access to RDS snapshots might be flagged. Verify these integrations and adjust the detection rule to recognize and exclude these trusted services.

**Response and remediation**

* Immediately revoke access to the AWS account or IAM role that initiated the unauthorized snapshot export to prevent further data exfiltration.
* Conduct a thorough review of AWS CloudTrail logs to identify any other unauthorized activities associated with the same account or IAM role, and assess the scope of the potential data breach.
* Notify the security team and relevant stakeholders about the incident, providing details of the unauthorized export and any other suspicious activities discovered.
* Restore the affected database from a known good backup if data integrity is suspected to be compromised, ensuring that the restored data is free from unauthorized changes.
* Implement stricter IAM policies and permissions to limit who can perform snapshot exports, ensuring that only authorized personnel have the necessary permissions.
* Enhance monitoring and alerting mechanisms to detect any future unauthorized snapshot export attempts, ensuring timely response to similar threats.
* Conduct a post-incident review to identify gaps in security controls and update incident response plans to improve readiness for future incidents.


## Setup [_setup_932]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5032]

```js
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:StartExportTask and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)



