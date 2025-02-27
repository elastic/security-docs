---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-iam-assume-role-policy-update.html
---

# AWS IAM Assume Role Policy Update [aws-iam-assume-role-policy-update]

Identifies AWS CloudTrail events where an IAM role’s trust policy has been updated. The trust policy is a JSON document that defines which principals are allowed to assume the role. An attacker may attempt to modify this policy to gain the privileges of the role. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule, which means it will only trigger once for each unique value of the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.flattened.request_parameters.roleName` fields that has not been seen making this API request within the last 14 days.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://labs.bishopfox.com/tech-blog/5-privesc-attack-vectors-in-aws](https://labs.bishopfox.com/tech-blog/5-privesc-attack-vectors-in-aws)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS IAM
* Use Case: Identity and Access Audit
* Resources: Investigation Guide
* Tactic: Privilege Escalation

**Version**: 210

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_45]

**Triage and analysis**

**Investigating AWS IAM Assume Role Policy Update**

An IAM role is an IAM identity that you can create in your account that has specific permissions. An IAM role is similar to an IAM user, in that it is an AWS identity with permission policies that determine what the identity can and cannot do in AWS. However, instead of being uniquely associated with one person, a role is intended to be assumable by anyone who needs it. Also, a role does not have standard long-term credentials such as a password or access keys associated with it. Instead, when you assume a role, it provides you with temporary security credentials for your role session.

The role trust policy is a JSON document in which you define the principals you trust to assume the role. This policy is a required resource-based policy that is attached to a role in IAM. An attacker may attempt to modify this policy by using the `UpdateAssumeRolePolicy` API action to gain the privileges of that role.

**Possible investigation steps**

* Review the `aws.cloudtrail.user_identity.arn` field to determine the user identity that performed the action.
* Review the `aws.cloudtrail.flattened.request_parameters.roleName` field to confirm the role that was updated.
* Within the `aws.cloudtrail.request_parameters` field, review the `policyDocument` to understand the changes made to the trust policy.
* If `aws.cloudtrail.user_identity.access_key_id` is present, investigate the access key used to perform the action as it may be compromised.
* Identify the user account that performed the action and whether it should perform this kind of action.
* Investigate other alerts associated with the user account during the past 48 hours.
* Contact the account and resource owners and confirm whether they are aware of this activity.
* Check if this operation was approved and performed according to the organization’s change management policy.
* If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services, and data accessed by the account in the last 24 hours.

**False positive analysis**

* False positives may occur due to the intended usage of the service. Tuning is needed in order to have higher confidence. Consider adding exceptions — preferably with a combination of the user agent and user ID conditions — to cover administrator activities and infrastructure as code tooling.

**Response and remediation**

* Initiate the incident response process based on the outcome of the triage.
* Disable or limit the account during the investigation and response.
* Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
* Identify the account role in the cloud environment.
* Assess the criticality of affected services and servers.
* Work with your IT team to identify and minimize the impact on users.
* Identify if the attacker is moving laterally and compromising other accounts, servers, or services.
* Identify any regulatory or legal ramifications related to this activity.
* Use AWS [policy versioning](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.md) to restore the trust policy to the desired state.
* Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords or delete API keys as needed to revoke the attacker’s access to the environment. Work with your IT teams to minimize the impact on business operations during these actions.
* Check if unauthorized new users were created, remove unauthorized new accounts, and request password resets for other IAM users.
* Consider enabling multi-factor authentication for users.
* Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
* Implement security best practices [outlined](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/) by AWS.
* Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Rule query [_rule_query_46]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "iam.amazonaws.com"
    and event.action: "UpdateAssumeRolePolicy"
    and event.outcome: "success"
    and not source.address: "cloudformation.amazonaws.com"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)



