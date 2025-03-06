---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-sts-assumeroot-by-rare-user-and-member-account.html
---

# AWS STS AssumeRoot by Rare User and Member Account [prebuilt-rule-8-17-4-aws-sts-assumeroot-by-rare-user-and-member-account]

Identifies when the STS `AssumeRoot` action is performed by a rare user in AWS. The AssumeRoot action allows users to assume the root member account role, granting elevated but specific permissions based on the task policy specified. Adversaries whom may have compromised user credentials, such as access and secret keys, can use this technique to escalate privileges and gain unauthorized access to AWS resources. This is a [New Terms](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#create-new-terms-rule) rule that identifies when the STS `AssumeRoot` action is performed by a user that rarely assumes this role and specific member account.

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

* [https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoot.html](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoot.html)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS STS
* Resources: Investigation Guide
* Use Case: Identity and Access Audit
* Tactic: Privilege Escalation

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4067]

**Triage and analysis**

**Investigating AWS STS AssumeRoot by Rare User and Member Account**

This rule identifies instances where AWS STS (Security Token Service) is used to assume a root role, granting temporary credentials for AWS resource access. While this action is often legitimate, it can be exploited by adversaries to obtain unauthorized access, escalate privileges, or move laterally within an AWS environment.

**Possible Investigation Steps**

* ***Identify the Actor and Assumed Role***:
* ***User Identity***: Review the `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.type` fields to determine who initiated the `AssumeRoot` action.
* ***Account Context***: Check the `aws.cloudtrail.recipient_account_id` field for the account affected by the action. This is likely the management account.
* ***Authentication***: If available, review the `aws.cloudtrail.user_identity.access_key_id` to identify the access key used for the action. This key may be compromised in the case of unauthorized activity.
* ***Resources***: Inspect `aws.cloudtrail.resources.type` and `aws.cloudtrail.resources.arn` to determine the resource or role assumed. This is the member account where the root role was assumed.
* ***Analyze Request Parameters***:
* ***Session Details***: Check `aws.cloudtrail.flattened.request_parameters.durationSeconds` for session duration.
* ***Permissions***: Review `aws.cloudtrail.flattened.request_parameters.taskPolicyArn` for the associated policy. These policies are predefined and grant specific permissions to the assumed root account.
* ***Target Entity***: Inspect the `aws.cloudtrail.flattened.request_parameters.targetPrincipal` field for the entity being accessed. This is typically the member account.
* ***Target Policy***: Inspect the `aws.cloudtrail.flattened.request_parameters.targetPolicyArn` field for the policy applied to temporary root credentials. This can help determine the scope of the permissions granted.
* ***Examine Response Details***:
* ***Credentials Issued***: Review `aws.cloudtrail.flattened.response_elements.credentials` to confirm credentials were issued and note their expiration (`expiration` field). The temporary access key can be used to pivot into other actions done by the assumed root account by searching for the value in `aws.cloudtrail.user_identity.access_key_id`.
* ***Inspect Source Details***:
* ***Source IP and Location***: Evaluate `source.address` and `source.geo` fields to confirm the request’s origin. Unusual locations might indicate unauthorized activity.
* ***User Agent***: Analyze `user_agent.original` to determine the tool or application used (e.g., AWS CLI, SDK, or custom tooling).
* ***Correlate with Related Events***:
* ***Concurrent Events***: Look for surrounding CloudTrail events that indicate follow-up actions, such as access to sensitive resources or privilege escalation attempts.
* ***Historical Activity***: Review historical activity for the `aws.cloudtrail.user_identity.arn` to determine if this action is anomalous.
* ***Evaluate Privilege Escalation Risk***:
* ***Role Privileges***: Inspect the privileges granted by the assumed role or task policy (`aws.cloudtrail.flattened.request_parameters.taskPolicyArn`).
* ***Operational Context***: Confirm whether the action aligns with routine operations or is unusual.

**False Positive Analysis**

* ***Authorized Administrative Activity***:
* Verify if the activity was initiated by an AWS administrator for legitimate purposes.
* ***Automated Workflows***:
* Identify if the action was part of an automated process or workflow.

**Response and Remediation**

1. ***Revoke Unauthorized Credentials***:

    * If malicious activity is identified, immediately revoke the session tokens and access keys associated with the `AssumeRoot` action.
    * It may be worth removing the compromised access key from the affected user or service account.

2. ***Enhance Monitoring***:

    * Increase the monitoring frequency for sensitive roles and actions, especially `AssumeRoot`.

3. ***Review IAM Policies***:

    * Limit permissions for accounts or roles to assume root and enforce multi-factor authentication (MFA) where applicable.

4. ***Contain and Investigate***:

    * Isolate affected accounts or roles and follow incident response procedures to determine the scope and impact of the activity.


**Additional Information**

For more information on AssumeRoot, refer to the [AWS STS documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoot.html).


## Rule query [_rule_query_5084]

```js
event.dataset: "aws.cloudtrail"
    and event.provider: "sts.amazonaws.com"
    and event.action: "AssumeRoot"
    and event.outcome: "success"
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



