---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-iam-administratoraccess-policy-attached-to-user.html
---

# AWS IAM AdministratorAccess Policy Attached to User [aws-iam-administratoraccess-policy-attached-to-user]

An adversary with access to a set of compromised credentials may attempt to persist or escalate privileges by attaching additional permissions to compromised user accounts. This rule looks for use of the IAM `AttachUserPolicy` API operation to attach the highly permissive `AdministratorAccess` AWS managed policy to an existing IAM user.

**Rule type**: esql

**Rule indices**: None

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.md)
* [https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AdministratorAccess.html](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AdministratorAccess.md)
* [https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/](https://hackingthe.cloud/aws/exploitation/iam_privilege_escalation/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS IAM
* Use Case: Identity and Access Audit
* Tactic: Privilege Escalation
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_44]

**Triage and analysis**

**Investigating AWS IAM AdministratorAccess Policy Attached to User**

The AWS IAM `AdministratorAccess` managed policy provides full access to all AWS services and resources. With access to the `iam:AttachUserPolicy` permission, a set of compromised credentials could be used to attach this policy to the current user for privilege escalation or another user as a means of persistence. This rule uses [ES|QL](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-esql-rule) to look for use of the `AttachUserPolicy` operation along with request_parameters where the policyName is `AdministratorAccess`.

**Possible investigation steps**

* Identify the account and its role in the environment.
* Review IAM permission policies for the user identity.
* Identify the applications or users that should use this account.
* Investigate other alerts associated with the account during the past 48 hours.
* Investigate abnormal values in the `user_agent.original` field by comparing them with the intended and authorized usage and historical data. Suspicious user agent values include non-SDK, AWS CLI, custom user agents, etc.
* Contact the account owner and confirm whether they are aware of this activity.
* Considering the source IP address and geolocation of the user who issued the command:
* Do they look normal for the calling user?
* If the source is an EC2 IP address, is it associated with an EC2 instance in one of your accounts or is the source IP from an EC2 instance that’s not under your control?
* If it is an authorized EC2 instance, is the activity associated with normal behavior for the instance role or roles? Are there any other alerts or signs of suspicious activity involving this instance?
* If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services, and data accessed by the account in the last 24 hours.
* Determine what other API calls were made by the user.
* Assess whether this behavior is prevalent in the environment by looking for similar occurrences involving other users.

**False positive analysis**

* False positives may occur due to the intended usage of the IAM `AdministratorAccess` managed policy. Verify the `aws.cloudtrail.user_identity.arn` should have the `iam:AttachUserPolicy` permission and that the `target.userName` should be given full administrative access.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Disable or limit the account during the investigation and response.
* Rotate user credentials
* Remove the `AdministratorAccess` policy from the affected user(s)
* Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
* Identify the account role in the cloud environment.
* Assess the criticality of affected services and servers.
* Work with your IT team to identify and minimize the impact on users.
* Identify if the attacker is moving laterally and compromising other accounts, servers, or services.
* Identify any regulatory or legal ramifications related to this activity.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified.
* Rotate secrets or delete API keys as needed to revoke the attacker’s access to the environment.
* Work with your IT teams to minimize the impact on business operations during these actions.
* Check if unauthorized new users were created, remove unauthorized new accounts, and request password resets for other IAM users.
* Consider enabling multi-factor authentication for users.
* Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
* Implement security best practices [outlined](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/) by AWS.
* Take the actions needed to return affected systems, data, or services to their normal operational levels.
* Identify the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_45]

```js
from logs-aws.cloudtrail-* metadata _id, _version, _index
| where event.provider == "iam.amazonaws.com" and event.action == "AttachUserPolicy" and event.outcome == "success"
| dissect aws.cloudtrail.request_parameters "{%{?policyArn}=%{?arn}:%{?aws}:%{?iam}::%{?aws}:%{?policy}/%{policyName},%{?userName}=%{target.userName}}"
| where policyName == "AdministratorAccess"
| keep
    @timestamp,
    cloud.region,
    event.provider,
    event.action,
    event.outcome,
    policyName,
    target.userName,
    aws.cloudtrail.request_parameters,
    aws.cloudtrail.user_identity.arn,
    related.user,
    user_agent.original,
    user.name,
    source.address
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: Additional Cloud Roles
    * ID: T1098.003
    * Reference URL: [https://attack.mitre.org/techniques/T1098/003/](https://attack.mitre.org/techniques/T1098/003/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: Additional Cloud Roles
    * ID: T1098.003
    * Reference URL: [https://attack.mitre.org/techniques/T1098/003/](https://attack.mitre.org/techniques/T1098/003/)



