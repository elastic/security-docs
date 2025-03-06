---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-iam-compromisedkeyquarantine-policy-attached-to-user.html
---

# AWS IAM CompromisedKeyQuarantine Policy Attached to User [prebuilt-rule-8-17-4-aws-iam-compromisedkeyquarantine-policy-attached-to-user]

This rule looks for use of the IAM `AttachUserPolicy` API operation to attach the `CompromisedKeyQuarantine` or `CompromisedKeyQuarantineV2` AWS managed policies to an existing IAM user. This policy denies access to certain actions and is applied by the AWS team in the event that an IAM user’s credentials have been compromised or exposed publicly.

**Rule type**: eql

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-6m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantine.html/](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantine.md/)
* [https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV2.html/](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV2.md/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS IAM
* Resources: Investigation Guide
* Use Case: Identity and Access Audit
* Tactic: Credential Access

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3982]

**Triage and analysis**

**Investigating AWS IAM CompromisedKeyQuarantine Policy Attached to User**

The AWS IAM `CompromisedKeyQuarantine` and `CompromisedKeyQuarantineV2` managed policies deny certain action and is applied by the AWS team to a user with exposed credentials. This action is accompanied by a support case which specifies instructions to follow before detaching the policy.

**Possible Investigation Steps**

* ***Identify Potentially Compromised Identity***: Review the `userName` parameter of the `aws.cloudtrail.request_parameters` to determine the quarantined IAM entity.
* ***Contextualize with AWS Support Case***: Review any information from AWS comtaining additional information about the quarantined account and the reasoning for quarantine.
* ***Follow Support Case Instructions***: Do not revert the quarantine policy attachment or delete the compromised keys. Instead folow the instructions given in your support case.
* ***Correlate with Other Activities***: Search for related CloudTrail events before and after this change to see if the same actor or IP address engaged in potentially suspicious activities.
* ***Interview Relevant Personnel***: If the compromised key belongs to a user, verify the intent and authorization for these correlated actions with the person or team responsible for managing the compromised key.

**False Positive Analysis**

* There shouldn’t be many false positives related to this action as it is inititated by AWS in response to compromised or publicly exposed credentials.

**Response and Remediation**

* ***Immediate Review and Reversal***: Update the user IAM permissions to remove the quarantine policy and disable the compromised credentials.
* ***Policy Update***: Review and possibly update your organization’s policies on credential storage to tighten control and prevent public exposure.
* ***Incident Response***: If malicious intent is confirmed, consider it a data breach incident and initiate the incident response protocol. This includes further investigation, containment, and recovery.

**Additional Information:**

For further guidance on managing and securing credentials in AWS environments, refer to the [AWS IAM User Guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html) regarding security best practices and guidance on [Remediating Potentially Compromised AWS Credentials](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html).


## Rule query [_rule_query_4999]

```js
any where event.dataset == "aws.cloudtrail"
   and event.action == "AttachUserPolicy"
   and event.outcome == "success"
   and stringContains(aws.cloudtrail.request_parameters, "AWSCompromisedKeyQuarantine")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Unsecured Credentials
    * ID: T1552
    * Reference URL: [https://attack.mitre.org/techniques/T1552/](https://attack.mitre.org/techniques/T1552/)



