---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-iam-role-deletion.html
---

# GCP IAM Role Deletion [prebuilt-rule-8-17-4-gcp-iam-role-deletion]

Identifies an Identity and Access Management (IAM) role deletion in Google Cloud Platform (GCP). A role contains a set of permissions that allows you to perform specific actions on Google Cloud resources. An adversary may delete an IAM role to inhibit access to accounts utilized by legitimate users.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-gcp*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://cloud.google.com/iam/docs/understanding-roles](https://cloud.google.com/iam/docs/understanding-roles)

**Tags**:

* Domain: Cloud
* Data Source: GCP
* Data Source: Google Cloud Platform
* Use Case: Identity and Access Audit
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4173]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP IAM Role Deletion**

Google Cloud Platform’s IAM roles define permissions for actions on resources, crucial for managing access. Adversaries might delete roles to disrupt legitimate user access, hindering operations. The detection rule monitors audit logs for successful role deletions, signaling potential unauthorized access removal, thus aiding in identifying and mitigating such security threats.

**Possible investigation steps**

* Review the audit logs for the specific event.action:google.iam.admin.v*.DeleteRole to identify the exact role that was deleted and the associated project or resource.
* Identify the user or service account responsible for the deletion by examining the actor information in the audit logs.
* Check the event.timestamp to determine when the role deletion occurred and correlate it with any other suspicious activities around the same time.
* Investigate the event.outcome:success to confirm that the role deletion was completed successfully and assess the potential impact on access and operations.
* Analyze the context of the deletion by reviewing recent changes or activities in the project or organization to understand if the deletion was part of a legitimate change or an unauthorized action.
* Contact the user or team responsible for the project to verify if the role deletion was intentional and authorized, and gather additional context if needed.

**False positive analysis**

* Routine administrative actions may trigger alerts when roles are deleted as part of regular maintenance or restructuring. To manage this, create exceptions for known administrative accounts or scheduled maintenance windows.
* Automated scripts or tools that manage IAM roles might cause false positives if they delete roles as part of their operation. Identify these scripts and exclude their actions from triggering alerts by using specific service accounts or tags.
* Deletion of temporary or test roles used in development environments can be mistaken for malicious activity. Implement filters to exclude actions within designated development projects or environments.
* Changes in organizational structure or policy might necessitate role deletions, which could be misinterpreted as threats. Document and communicate these changes to the security team to adjust monitoring rules accordingly.
* Third-party integrations or services that manage IAM roles could inadvertently cause false positives. Ensure these services are properly documented and their actions are whitelisted if deemed non-threatening.

**Response and remediation**

* Immediately revoke any active sessions and credentials associated with the deleted IAM role to prevent unauthorized access.
* Restore the deleted IAM role from a backup or recreate it with the same permissions to ensure legitimate users regain access.
* Conduct a thorough review of recent IAM activity logs to identify any unauthorized changes or suspicious activities related to IAM roles.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Implement additional monitoring on IAM role changes to detect and alert on any future unauthorized deletions promptly.
* Review and tighten IAM role permissions to ensure the principle of least privilege is enforced, reducing the risk of similar incidents.
* Consider enabling additional security features such as multi-factor authentication (MFA) for accounts with permissions to modify IAM roles.


## Setup [_setup_1043]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5182]

```js
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteRole and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Account Access Removal
    * ID: T1531
    * Reference URL: [https://attack.mitre.org/techniques/T1531/](https://attack.mitre.org/techniques/T1531/)



