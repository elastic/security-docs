---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-service-account-disabled.html
---

# GCP Service Account Disabled [prebuilt-rule-8-17-4-gcp-service-account-disabled]

Identifies when a service account is disabled in Google Cloud Platform (GCP). A service account is a special type of account used by an application or a virtual machine (VM) instance, not a person. Applications use service accounts to make authorized API calls, authorized as either the service account itself, or as G Suite or Cloud Identity users through domain-wide delegation. An adversary may disable a service account in order to disrupt to disrupt their target’s business operations.

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

## Investigation guide [_investigation_guide_4175]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Service Account Disabled**

In Google Cloud Platform, service accounts are crucial for applications and VMs to perform authorized actions without user intervention. Adversaries may disable these accounts to disrupt services, impacting business operations. The detection rule identifies successful disablement actions in audit logs, signaling potential malicious activity by correlating specific event actions and outcomes, thus enabling timely investigation and response.

**Possible investigation steps**

* Review the audit logs for the specific event.action:google.iam.admin.v*.DisableServiceAccount to identify the exact time and source of the disablement action.
* Identify the user or service account that performed the disablement by examining the actor information in the audit logs.
* Check for any recent changes or unusual activities associated with the disabled service account, such as modifications to permissions or roles.
* Investigate any related events or actions in the audit logs around the same timeframe to identify potential patterns or additional suspicious activities.
* Assess the impact of the disabled service account on business operations by determining which applications or services were using the account.
* Contact relevant stakeholders or application owners to verify if the disablement was authorized or if it was an unexpected action.

**False positive analysis**

* Routine maintenance activities by administrators may involve disabling service accounts temporarily. To manage this, create exceptions for known maintenance periods or specific administrator actions.
* Automated scripts or tools used for testing or deployment might disable service accounts as part of their process. Identify these scripts and exclude their actions from triggering alerts by using specific identifiers or tags.
* Organizational policy changes or restructuring might lead to intentional service account disablement. Document these changes and update the detection rule to recognize these legitimate actions.
* Service accounts associated with deprecated or retired applications may be disabled as part of cleanup efforts. Maintain an updated list of such applications and exclude related disablement actions from alerts.

**Response and remediation**

* Immediately isolate the affected service account by revoking its permissions to prevent further unauthorized actions.
* Review the audit logs to identify any other suspicious activities associated with the disabled service account and assess the potential impact on business operations.
* Re-enable the service account if it is determined to be legitimate and necessary for business functions, ensuring that it is secured with appropriate permissions and monitoring.
* Notify the security team and relevant stakeholders about the incident for awareness and further investigation.
* Implement additional monitoring and alerting for similar disablement actions on service accounts to detect and respond to future incidents promptly.
* Conduct a root cause analysis to understand how the service account was disabled and address any security gaps or misconfigurations that allowed the incident to occur.
* Consider implementing additional security measures such as multi-factor authentication and least privilege access to enhance the protection of service accounts.


## Setup [_setup_1045]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5184]

```js
event.dataset:gcp.audit and event.action:google.iam.admin.v*.DisableServiceAccount and event.outcome:success
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



