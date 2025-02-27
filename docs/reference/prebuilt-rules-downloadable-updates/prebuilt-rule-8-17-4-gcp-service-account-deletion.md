---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-service-account-deletion.html
---

# GCP Service Account Deletion [prebuilt-rule-8-17-4-gcp-service-account-deletion]

Identifies when a service account is deleted in Google Cloud Platform (GCP). A service account is a special type of account used by an application or a virtual machine (VM) instance, not a person. Applications use service accounts to make authorized API calls, authorized as either the service account itself, or as G Suite or Cloud Identity users through domain-wide delegation. An adversary may delete a service account in order to disrupt their target’s business operations.

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

* [https://cloud.google.com/iam/docs/service-accounts](https://cloud.google.com/iam/docs/service-accounts)

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

## Investigation guide [_investigation_guide_4174]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Service Account Deletion**

In Google Cloud Platform, service accounts are crucial for enabling applications and VMs to perform authorized actions without user intervention. Adversaries may exploit this by deleting service accounts to disrupt operations or remove access. The detection rule monitors audit logs for successful service account deletions, flagging potential malicious activity to ensure timely investigation and response.

**Possible investigation steps**

* Review the audit logs for the specific event.action:google.iam.admin.v*.DeleteServiceAccount to identify the exact time and source of the deletion.
* Identify the user or service account that initiated the deletion by examining the actor information in the audit logs.
* Check the event.dataset:gcp.audit logs for any preceding or subsequent actions by the same user or service account to determine if there is a pattern of suspicious activity.
* Investigate the context of the deleted service account, including its permissions and the resources it had access to, to assess the potential impact of its deletion.
* Contact the relevant team or individual responsible for the service account to verify if the deletion was authorized and intentional.
* If unauthorized, review access controls and consider implementing additional security measures to prevent future unauthorized deletions.

**False positive analysis**

* Routine maintenance or updates may involve the deletion and recreation of service accounts. To manage this, create exceptions for known maintenance activities by excluding specific service account names or associated project IDs during these periods.
* Automated scripts or deployment tools might delete and recreate service accounts as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts by filtering based on the user or service account executing the script.
* Organizational policy changes or restructuring can lead to legitimate service account deletions. Coordinate with the IT or security team to document these changes and adjust the detection rule to exclude these known events.
* Test environments often involve frequent creation and deletion of service accounts. Exclude test project IDs or environments from the detection rule to prevent unnecessary alerts.

**Response and remediation**

* Immediately revoke any permissions associated with the deleted service account to prevent unauthorized access or actions by adversaries exploiting the deletion.
* Restore the deleted service account if possible, using GCP’s undelete feature, to minimize disruption to business operations and restore normal functionality.
* Review and audit recent IAM activity logs to identify any unauthorized or suspicious actions that may have preceded or followed the service account deletion.
* Notify the security team and relevant stakeholders about the incident to ensure awareness and facilitate coordinated response efforts.
* Implement additional monitoring on critical service accounts to detect and alert on any further unauthorized deletion attempts.
* Conduct a root cause analysis to determine how the service account deletion was initiated and address any security gaps or misconfigurations that allowed it.
* Enhance access controls and consider implementing multi-factor authentication for actions involving service account management to prevent similar incidents in the future.


## Setup [_setup_1044]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5183]

```js
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DeleteServiceAccount and event.outcome:success
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



