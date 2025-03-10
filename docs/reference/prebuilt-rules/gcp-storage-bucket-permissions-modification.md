---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/gcp-storage-bucket-permissions-modification.html
---

# GCP Storage Bucket Permissions Modification [gcp-storage-bucket-permissions-modification]

Identifies when the Identity and Access Management (IAM) permissions are modified for a Google Cloud Platform (GCP) storage bucket. An adversary may modify the permissions on a storage bucket to weaken their target’s security controls or an administrator may inadvertently modify the permissions, which could lead to data exposure or loss.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-gcp*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.google.com/storage/docs/access-control/iam-permissions](https://cloud.google.com/storage/docs/access-control/iam-permissions)

**Tags**:

* Domain: Cloud
* Data Source: GCP
* Data Source: Google Cloud Platform
* Use Case: Identity and Access Audit
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_372]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Storage Bucket Permissions Modification**

Google Cloud Platform (GCP) storage buckets are essential for storing and managing data in the cloud. IAM permissions control access to these buckets, ensuring data security. Adversaries may alter these permissions to bypass security measures, leading to unauthorized data access or exposure. The detection rule identifies successful permission changes, signaling potential misuse or accidental misconfigurations, aiding in timely security audits and responses.

**Possible investigation steps**

* Review the event logs for the specific action "storage.setIamPermissions" to identify which IAM permissions were modified and by whom.
* Check the event.outcome field to confirm the success of the permission change and correlate it with any recent access attempts or data access patterns.
* Investigate the identity of the user or service account that performed the permission change to determine if it aligns with expected administrative activities.
* Assess the current IAM policy of the affected storage bucket to understand the new permissions and evaluate any potential security risks or exposure.
* Cross-reference the timing of the permission change with other security events or alerts to identify any suspicious activity or patterns.
* Consult with the bucket owner or relevant stakeholders to verify if the permission change was authorized and necessary for operational purposes.

**False positive analysis**

* Routine administrative updates to IAM permissions can trigger alerts. To manage this, create exceptions for known maintenance windows or specific administrative accounts that regularly perform these updates.
* Automated scripts or tools that adjust permissions as part of their normal operation may cause false positives. Identify these scripts and exclude their actions from triggering alerts by using specific service accounts or tags.
* Changes made by trusted third-party services integrated with GCP might be flagged. Review and whitelist these services if they are verified and necessary for business operations.
* Temporary permission changes for troubleshooting or testing purposes can be mistaken for malicious activity. Document and schedule these changes, and exclude them from alerts during the specified timeframes.
* Permissions modified by cloud management platforms or orchestration tools should be reviewed. If these tools are part of standard operations, consider excluding their actions from the detection rule.

**Response and remediation**

* Immediately revoke any unauthorized IAM permissions changes by restoring the previous known good configuration for the affected GCP storage bucket.
* Conduct a thorough review of the IAM policy change logs to identify the source and nature of the modification, focusing on the user or service account responsible for the change.
* Isolate the affected storage bucket from external access until the permissions are verified and secured to prevent further unauthorized access.
* Notify the security team and relevant stakeholders about the incident, providing details of the unauthorized changes and the steps taken to mitigate the risk.
* Implement additional monitoring on the affected storage bucket and related IAM policies to detect any further unauthorized changes or suspicious activities.
* Review and update IAM policies to ensure the principle of least privilege is enforced, reducing the risk of similar incidents in the future.
* If the incident is suspected to be part of a larger attack, escalate to incident response teams for a comprehensive investigation and potential involvement of law enforcement if necessary.


## Setup [_setup_236]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_404]

```js
event.dataset:gcp.audit and event.action:"storage.setIamPermissions" and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: File and Directory Permissions Modification
    * ID: T1222
    * Reference URL: [https://attack.mitre.org/techniques/T1222/](https://attack.mitre.org/techniques/T1222/)



