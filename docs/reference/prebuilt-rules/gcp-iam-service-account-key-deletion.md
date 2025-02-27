---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/gcp-iam-service-account-key-deletion.html
---

# GCP IAM Service Account Key Deletion [gcp-iam-service-account-key-deletion]

Identifies the deletion of an Identity and Access Management (IAM) service account key in Google Cloud Platform (GCP). Each service account is associated with two sets of public/private RSA key pairs that are used to authenticate. If a key is deleted, the application will no longer be able to access Google Cloud resources using that key. A security best practice is to rotate your service account keys regularly.

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

* [https://cloud.google.com/iam/docs/service-accounts](https://cloud.google.com/iam/docs/service-accounts)
* [https://cloud.google.com/iam/docs/creating-managing-service-account-keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys)

**Tags**:

* Domain: Cloud
* Data Source: GCP
* Data Source: Google Cloud Platform
* Use Case: Identity and Access Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_358]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP IAM Service Account Key Deletion**

In GCP, IAM service account keys authenticate applications to access resources. Regular key rotation is crucial for security. Adversaries might delete keys to disrupt services or cover tracks after unauthorized access. The detection rule monitors audit logs for successful key deletions, flagging potential misuse or policy violations, aiding in timely investigation and response.

**Possible investigation steps**

* Review the audit logs for the specific event.action: google.iam.admin.v*.DeleteServiceAccountKey to identify the service account key that was deleted.
* Check the event.outcome: success to confirm the key deletion was successful and not an attempted action.
* Identify the user or service account responsible for the deletion by examining the actor information in the audit logs.
* Investigate the context around the deletion event, including the timestamp and any preceding or subsequent actions in the logs, to understand the sequence of events.
* Verify if the key deletion aligns with the organization’s key rotation policy or if it appears suspicious or unauthorized.
* Assess the impact of the key deletion on applications or services that rely on the affected service account for authentication.
* If unauthorized activity is suspected, initiate a broader investigation into potential unauthorized access or other malicious activities involving the affected service account.

**False positive analysis**

* Routine key rotation activities by administrators can trigger alerts. To manage this, establish a baseline of expected key rotation schedules and exclude these from alerts.
* Automated scripts or tools that perform regular maintenance and key management might cause false positives. Identify these scripts and whitelist their actions in the monitoring system.
* Service account keys associated with non-critical or test environments may be deleted frequently as part of normal operations. Consider excluding these environments from the alerting criteria to reduce noise.
* Temporary service accounts used for short-term projects or testing may have keys deleted as part of their lifecycle. Document these accounts and adjust the detection rule to ignore deletions from these specific accounts.

**Response and remediation**

* Immediately revoke any remaining access for the compromised service account to prevent further unauthorized access to Google Cloud resources.
* Investigate the audit logs to identify any unauthorized actions performed using the deleted key and assess the impact on affected resources.
* Recreate the deleted service account key if necessary, ensuring that the new key is securely stored and access is restricted to authorized personnel only.
* Implement additional monitoring on the affected service account to detect any further suspicious activities or unauthorized access attempts.
* Escalate the incident to the security operations team for a comprehensive review and to determine if further investigation or response is required.
* Review and update the key rotation policy to ensure that service account keys are rotated more frequently and securely managed to prevent similar incidents in the future.


## Setup [_setup_222]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_390]

```js
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteServiceAccountKey and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



