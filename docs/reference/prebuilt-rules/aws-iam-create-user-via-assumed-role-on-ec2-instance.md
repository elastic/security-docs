---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-iam-create-user-via-assumed-role-on-ec2-instance.html
---

# AWS IAM Create User via Assumed Role on EC2 Instance [aws-iam-create-user-via-assumed-role-on-ec2-instance]

Detects the creation of an AWS Identity and Access Management (IAM) user initiated by an assumed role on an EC2 instance. Assumed roles allow users or services to temporarily adopt different AWS permissions, but the creation of IAM users through these roles—particularly from within EC2 instances—may indicate a compromised instance. Adversaries might exploit such permissions to establish persistence by creating new IAM users under unauthorized conditions.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.md)
* [https://www.dionach.com/en-us/breaking-into-the-cloud-red-team-tactics-for-aws-compromise/](https://www.dionach.com/en-us/breaking-into-the-cloud-red-team-tactics-for-aws-compromise/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS IAM
* Use Case: Identity and Access Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_48]

**Triage and analysis**

**Investigating AWS IAM Create User via Assumed Role on EC2 Instance**

This rule detects when an AWS Identity and Access Management (IAM) user is created through an assumed role on an EC2 instance. This action may indicate a potentially compromised instance where an adversary could be using the instance’s permissions to create a new IAM user, enabling persistent unauthorized access.

**Possible Investigation Steps**

* ***Identify the Assumed Role and Initiating Instance***:
* ***Role and Instance***: Examine the `aws.cloudtrail.user_identity.arn` field to determine the specific EC2 instance and role used for this action (e.g., `arn:aws:sts::[account-id]:assumed-role/[role-name]/[instance-id]`). Verify if this behavior aligns with expected usage or represents an anomaly.
* ***Session Context***: Check the `session_issuer` fields in `aws.cloudtrail.user_identity.session_context` for details about the role assumed by the instance, along with `mfa_authenticated` to determine if Multi-Factor Authentication (MFA) was used.
* ***Analyze the Target IAM User***:
* ***New User Details***: Inspect `aws.cloudtrail.flattened.request_parameters.userName` to see the username that was created. Look at `aws.cloudtrail.flattened.response_elements.user.userName` for confirmation of successful user creation, and validate if the user is expected or authorized.
* ***Review Creation Time and Context***: Compare the creation time (`@timestamp`) of the user with other activities from the same instance and role to assess if this creation was part of a larger chain of actions.
* ***Check User Agent and Tooling***:
* ***User Agent Analysis***: Review `user_agent.original` to see if AWS CLI, SDK, or other tooling was used for this request. Identifiers such as `aws-cli`, `boto3`, or similar SDK names can indicate the method used, which may differentiate automation from interactive actions.
* ***Source IP and Location***: Use the `source.address` and `source.geo` fields to identify the IP address and geographic location of the event. Verify if this aligns with expected access patterns for your environment.
* ***Evaluate for Persistence Indicators***:
* ***Role Permissions***: Check the permissions associated with the assumed role (`arn:aws:iam::[account-id]:role/[role-name]`) to determine if creating IAM users is a legitimate activity for this role.
* ***Automated Role Patterns***: If the assumed role or instance typically creates IAM users for automation purposes, validate this action against historical records to confirm if the event is consistent with normal patterns.
* ***Review Related CloudTrail Events***:
* ***Additional IAM Actions***: Investigate for other recent IAM or CloudTrail events tied to this role or instance, especially `CreateAccessKey` or `AttachUserPolicy` actions. These could signal further attempts to empower or utilize the newly created user.
* ***Correlate with Other Suspicious Activities***: Determine if other roles or instances recently initiated similar unusual actions, such as privilege escalations or data access.

**False Positive Analysis**

* ***Expected Automation***: Assumed roles may be used by legitimate automated systems that create users for specific workflows. Confirm if this event aligns with known automation activities.
* ***User Agent and Role Exceptions***: If this action is routine for specific roles or user agents (e.g., `aws-cli`, `boto3`), consider adding those roles or user agents to a monitored exception list for streamlined review.

**Response and Remediation**

* ***Immediate Access Review***: If user creation was unauthorized, restrict the assumed role’s permissions to prevent further user creation.
* ***Delete Unauthorized Users***: Confirm and remove any unauthorized IAM users, adjusting IAM policies to reduce similar risks.
* ***Enhance Monitoring and Alerts***: Enable enhanced logging or real-time alerts for this role or instance to detect further unauthorized access attempts.
* ***Policy Update***: Consider updating IAM policies associated with roles on EC2 instances to limit sensitive actions like IAM user creation.

**Additional Information**

For further guidance on managing IAM roles and permissions within AWS environments, refer to the [AWS IAM documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.md) and AWS best practices for security.


## Rule query [_rule_query_49]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "iam.amazonaws.com"
    and event.action: "CreateUser"
    and event.outcome: "success"
    and aws.cloudtrail.user_identity.type: "AssumedRole"
    and aws.cloudtrail.user_identity.arn: *i-*
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



