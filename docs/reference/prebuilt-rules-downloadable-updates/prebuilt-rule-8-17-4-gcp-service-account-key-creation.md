---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-gcp-service-account-key-creation.html
---

# GCP Service Account Key Creation [prebuilt-rule-8-17-4-gcp-service-account-key-creation]

Identifies when a new key is created for a service account in Google Cloud Platform (GCP). A service account is a special type of account used by an application or a virtual machine (VM) instance, not a person. Applications use service accounts to make authorized API calls, authorized as either the service account itself, or as G Suite or Cloud Identity users through domain-wide delegation. If private keys are not tracked and managed properly, they can present a security risk. An adversary may create a new key for a service account in order to attempt to abuse the permissions assigned to that account and evade detection.

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

## Investigation guide [_investigation_guide_4179]

**Triage and analysis**

[TBC: QUOTE]
**Investigating GCP Service Account Key Creation**

In GCP, service accounts are crucial for applications to authenticate and interact with Google services securely. They use cryptographic keys for API access, which, if mismanaged, can be exploited by adversaries to gain unauthorized access. The detection rule monitors audit logs for new key creations, flagging potential misuse by identifying successful key generation events, thus helping to mitigate risks associated with unauthorized access.

**Possible investigation steps**

* Review the audit logs for the specific event.action: google.iam.admin.v*.CreateServiceAccountKey to identify the service account involved in the key creation.
* Check the event.dataset:gcp.audit logs to determine the user or process that initiated the key creation and verify if it aligns with expected behavior or scheduled tasks.
* Investigate the permissions and roles assigned to the service account to assess the potential impact of the new key being used maliciously.
* Examine the event.outcome:success logs to confirm the successful creation of the key and cross-reference with any recent changes or deployments that might justify the key creation.
* Contact the owner or responsible team for the service account to verify if the key creation was authorized and necessary for their operations.
* Review any recent alerts or incidents related to the service account to identify patterns or repeated unauthorized activities.

**False positive analysis**

* Routine key rotations by automated processes can trigger alerts. To manage this, identify and whitelist these processes by their service account names or associated metadata.
* Development and testing environments often generate new keys frequently. Exclude these environments from alerts by using environment-specific tags or labels.
* Scheduled maintenance activities by cloud administrators may involve key creation. Document these activities and create exceptions based on the timing and user accounts involved.
* Third-party integrations that require periodic key updates can cause false positives. Maintain a list of trusted third-party services and exclude their key creation events from alerts.
* Internal tools or scripts that programmatically create keys for operational purposes should be reviewed and, if deemed safe, added to an exception list based on their execution context.

**Response and remediation**

* Immediately revoke the newly created service account key to prevent unauthorized access. This can be done through the GCP Console or using the gcloud command-line tool.
* Conduct a thorough review of the service account’s permissions to ensure they are aligned with the principle of least privilege. Remove any unnecessary permissions that could be exploited.
* Investigate the source of the key creation event by reviewing audit logs to identify the user or process responsible for the action. Determine if the action was authorized or if it indicates a potential compromise.
* If unauthorized access is suspected, rotate all keys associated with the affected service account and any other potentially compromised accounts to mitigate further risk.
* Implement additional monitoring and alerting for unusual service account activities, such as unexpected key creations or permission changes, to enhance detection of similar threats in the future.
* Escalate the incident to the security team for further investigation and to determine if additional containment or remediation actions are necessary, including notifying affected stakeholders if a breach is confirmed.


## Setup [_setup_1049]

The GCP Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5188]

```js
event.dataset:gcp.audit and event.action:google.iam.admin.v*.CreateServiceAccountKey and event.outcome:success
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



