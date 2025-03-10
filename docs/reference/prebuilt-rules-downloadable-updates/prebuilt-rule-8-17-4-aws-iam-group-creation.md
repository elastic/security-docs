---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-iam-group-creation.html
---

# AWS IAM Group Creation [prebuilt-rule-8-17-4-aws-iam-group-creation]

Identifies the creation of a group in AWS Identity and Access Management (IAM). Groups specify permissions for multiple users. Any user in a group automatically has the permissions that are assigned to the group.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/create-group.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/create-group.md)
* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS IAM
* Use Case: Identity and Access Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4043]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS IAM Group Creation**

AWS IAM allows organizations to manage user access and permissions securely. Groups in IAM simplify permission management by allowing multiple users to inherit the same permissions. However, adversaries may exploit this by creating unauthorized groups to gain persistent access. The detection rule monitors successful group creation events, flagging potential misuse by correlating specific AWS CloudTrail logs, thus aiding in identifying unauthorized access attempts.

**Possible investigation steps**

* Review the AWS CloudTrail logs for the specific event.provider: iam.amazonaws.com and event.action: CreateGroup to identify the user or service that initiated the group creation.
* Check the event.dataset: aws.cloudtrail logs for any associated event.outcome: success entries to confirm the successful creation of the group.
* Investigate the permissions assigned to the newly created group to assess if they include any sensitive or high-privilege permissions that could pose a security risk.
* Identify and review the IAM user or role that created the group to determine if they have a legitimate reason for this action and if their activity aligns with their typical behavior.
* Cross-reference the group creation event with other recent IAM activities, such as user additions to the group or changes to group policies, to detect any suspicious patterns or anomalies.
* Consult with relevant stakeholders or the user responsible for the group creation to verify the legitimacy of the action and gather additional context if necessary.

**False positive analysis**

* Routine administrative actions by authorized personnel can trigger alerts. Regularly review and document legitimate group creation activities to differentiate them from unauthorized actions.
* Automated scripts or tools used for infrastructure management may create groups as part of their normal operation. Identify and whitelist these scripts to prevent unnecessary alerts.
* Temporary groups created for short-term projects or testing purposes might be flagged. Implement a naming convention for such groups and exclude them from alerts based on this pattern.
* Scheduled tasks or maintenance activities that involve group creation should be logged and approved in advance. Use these logs to create exceptions in the detection rule.
* Third-party integrations or services that require group creation for functionality can cause false positives. Verify these integrations and adjust the rule to exclude their known actions.

**Response and remediation**

* Immediately review the AWS CloudTrail logs to confirm the unauthorized creation of the IAM group and identify the user or service responsible for the action.
* Revoke any permissions associated with the newly created IAM group to prevent further unauthorized access or actions.
* Temporarily disable or delete the unauthorized IAM group to contain the threat and prevent any potential misuse.
* Conduct a thorough audit of recent IAM changes to identify any other unauthorized activities or anomalies that may indicate further compromise.
* Escalate the incident to the security operations team for a detailed investigation and to assess the potential impact on the organization’s security posture.
* Implement additional monitoring and alerting for IAM group creation events to enhance detection capabilities and prevent similar incidents in the future.
* Review and update IAM policies and permissions to ensure they follow the principle of least privilege, reducing the risk of unauthorized access.


## Setup [_setup_946]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5060]

```js
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:CreateGroup and event.outcome:success
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

* Sub-technique:

    * Name: Cloud Account
    * ID: T1136.003
    * Reference URL: [https://attack.mitre.org/techniques/T1136/003/](https://attack.mitre.org/techniques/T1136/003/)



