---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-service-account-creation.html
---

# GCP Service Account Creation [prebuilt-rule-8-17-4-gcp-service-account-creation]

Identifies when a new service account is created in Google Cloud Platform (GCP). A service account is a special type of account used by an application or a virtual machine (VM) instance, not a person. Applications use service accounts to make authorized API calls, authorized as either the service account itself, or as G Suite or Cloud Identity users through domain-wide delegation. If service accounts are not tracked and managed properly, they can present a security risk. An adversary may create a new service account to use during their operations in order to avoid using a standard user account and attempt to evade detection.

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

## Investigation guide [_investigation_guide_4180]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Service Account Creation**

In GCP, service accounts enable applications and VMs to interact with APIs securely. While essential for automation, they can be exploited if improperly managed. Adversaries might create service accounts to gain persistent access without detection. The detection rule monitors audit logs for successful service account creations, flagging potential unauthorized activities for further investigation.

**Possible investigation steps**

* Review the audit logs for the specific event.action:google.iam.admin.v*.CreateServiceAccount to identify the time and source of the service account creation.
* Check the identity of the user or service that initiated the service account creation to determine if it aligns with expected administrative activities.
* Investigate the permissions and roles assigned to the newly created service account to assess if they are excessive or unusual for its intended purpose.
* Correlate the service account creation event with other recent activities in the environment to identify any suspicious patterns or anomalies.
* Verify if the service account is being used by any unauthorized applications or VMs by reviewing recent API calls and access logs associated with the account.

**False positive analysis**

* Routine service account creation by automated deployment tools or scripts can trigger false positives. Identify and document these tools, then create exceptions in the monitoring system to exclude these known activities.
* Service accounts created by trusted internal teams for legitimate projects may also be flagged. Establish a process for these teams to notify security personnel of planned service account creations, allowing for pre-approval and exclusion from alerts.
* Scheduled maintenance or updates that involve creating temporary service accounts can result in false positives. Coordinate with IT operations to understand their schedules and adjust monitoring rules to accommodate these activities.
* Third-party integrations that require service accounts might be mistakenly flagged. Maintain an inventory of authorized third-party services and their associated service accounts to quickly verify and exclude these from alerts.

**Response and remediation**

* Immediately disable the newly created service account to prevent any unauthorized access or actions.
* Review the IAM policy and permissions associated with the service account to ensure no excessive privileges were granted.
* Conduct a thorough audit of recent activities performed by the service account to identify any suspicious or unauthorized actions.
* Notify the security team and relevant stakeholders about the potential security incident for further investigation and coordination.
* Implement additional monitoring and alerting for service account creations to detect similar activities in the future.
* If malicious activity is confirmed, follow incident response procedures to contain and remediate any impact, including revoking access and conducting a security review of affected resources.
* Document the incident and response actions taken to improve future detection and response capabilities.


## Setup [_setup_1050]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5189]

```js
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateServiceAccount and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create Account
    * ID: T1136
    * Reference URL: [https://attack.mitre.org/techniques/T1136/](https://attack.mitre.org/techniques/T1136/)



