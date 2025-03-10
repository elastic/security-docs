---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-iam-customer-managed-policy-attached-to-role-by-rare-user.html
---

# AWS IAM Customer-Managed Policy Attached to Role by Rare User [prebuilt-rule-8-17-4-aws-iam-customer-managed-policy-attached-to-role-by-rare-user]

Detects when an AWS Identity and Access Management (IAM) customer-managed policy is attached to a role by an unusual or unauthorized user. Customer-managed policies are policies created and controlled within an AWS account, granting specific permissions to roles or users when attached. This rule identifies potential privilege escalation by flagging cases where a customer-managed policy is attached to a role by an unexpected actor, which could signal unauthorized access or misuse. Attackers may attach policies to roles to expand permissions and elevate their privileges within the AWS environment. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule that uses the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.flattened.request_parameters.roleName` fields to check if the combination of the actor ARN and target role name has not been seen in the last 14 days.

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

* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS IAM
* Resources: Investigation Guide
* Use Case: Identity and Access Audit
* Tactic: Privilege Escalation

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4062]

**Triage and analysis**

**Investigating AWS IAM Customer-Managed Policy Attached to Role by Rare User**

This rule detects when a customer-managed IAM policy is attached to a role by an unusual or unauthorized user. This activity may indicate a potential privilege escalation attempt within the AWS environment. Adversaries could attach policies to roles to expand permissions, thereby increasing their capabilities and achieving elevated access.

**Possible Investigation Steps**

* ***Identify the Initiating User and Target Role***:
* ***User Identity***: Examine the `aws.cloudtrail.user_identity.arn` field to determine the user who initiated the policy attachment. Confirm if this user typically has permissions to modify IAM roles and if their activity is consistent with their usual responsibilities.
* ***Target Role***: Review `aws.cloudtrail.flattened.request_parameters.roleName` to identify the role to which the policy was attached. Assess whether modifying this role is expected for this user or if this action is unusual in your environment.
* ***Analyze the Attached Policy***:
* ***Policy ARN***: Inspect the `aws.cloudtrail.flattened.request_parameters.policyArn` field to identify the specific customer-managed policy attached to the role. Evaluate if this policy grants sensitive permissions, especially permissions that could enable privileged actions or data access.
* ***Policy Permissions***: Examine the policy content to determine the scope of permissions granted. Policies enabling actions like `s3:*`, `ec2:*`, or `iam:*` could be leveraged for broader access, persistence, or lateral movement.
* ***Review Source and User Agent Details***:
* ***Source IP and Location***: Analyze the `source.address` and `source.geo` fields to confirm the IP address and geographic location where the policy attachment originated. Verify if this matches expected locations for the initiating user.
* ***User Agent Analysis***: Examine `user_agent.original` to determine if AWS CLI, SDK, or other tooling was used to perform this action. Tool identifiers like `aws-cli` or `boto3` may indicate automation, while others may suggest interactive sessions.
* ***Evaluate Anomalous Behavior Patterns***:
* ***User’s Historical Activity***: Check if the initiating user has a history of attaching policies to roles. An unusual pattern in policy attachments could indicate suspicious behavior, especially if the user lacks authorization.
* ***Role Modification History***: Investigate if the targeted role is frequently modified by this or other users. Repeated, unauthorized modifications to a role could signal an attempt to maintain elevated access.
* ***Correlate with Related CloudTrail Events***:
* ***Other IAM or CloudTrail Activities***: Look for recent actions associated with the same user or role by reviewing `event.action` by `event.provider` to identify which AWS services were accessed. This may provide context on the user’s intent or additional actions taken.
* ***Broader Suspicious Patterns***: Identify if similar anomalous events have recently occurred, potentially suggesting a coordinated or escalating attack pattern within the AWS account.

**False Positive Analysis**

* ***Authorized Administrative Actions***: IAM administrators may legitimately attach policies to roles as part of routine role management. Verify if the user is authorized and if the activity aligns with expected administrative tasks.
* ***Role-Specific Modifications***: Roles that frequently undergo policy updates may trigger this rule during standard operations. Consider monitoring for patterns or establishing known exceptions for specific users or roles where appropriate.

**Response and Remediation**

* ***Immediate Access Review***: If the policy attachment is unauthorized, consider detaching the policy and reviewing the permissions granted to the initiating user.
* ***Restrict Role Modification Permissions***: Limit which users or roles can attach policies to critical IAM roles. Apply least privilege principles to reduce the risk of unauthorized policy changes.
* ***Enhance Monitoring and Alerts***: Enable real-time alerts and monitoring on IAM policy modifications to detect similar actions promptly.
* ***Regular Policy Audits***: Conduct periodic audits of IAM policies and role permissions to ensure that unauthorized changes are quickly identified and addressed.

**Additional Information**

For more information on managing IAM policies and roles in AWS environments, refer to the [AWS IAM Documentation](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.md) and AWS security best practices.


## Rule query [_rule_query_5079]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "iam.amazonaws.com"
    and event.action: "AttachRolePolicy"
    and event.outcome: "success"
    and not aws.cloudtrail.flattened.request_parameters.policyArn: arn\:aws\:iam\:\:aws\:policy*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Temporary Elevated Cloud Access
    * ID: T1548.005
    * Reference URL: [https://attack.mitre.org/techniques/T1548/005/](https://attack.mitre.org/techniques/T1548/005/)



