---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-1-aws-iam-login-profile-added-for-root.html
---

# AWS IAM Login Profile Added for Root [prebuilt-rule-8-17-1-aws-iam-login-profile-added-for-root]

Detects when an AWS IAM login profile is added to a root user account and is self-assigned. Adversaries, with temporary access to the root account, may add a login profile to the root user account to maintain access even if the original access key is rotated or disabled.

**Rule type**: esql

**Rule indices**: None

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS IAM
* Use Case: Identity and Access Audit
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3886]

**Investigating AWS IAM Login Profile Added for Root**

This rule detects when a login profile is added to the AWS root account. Adding a login profile to the root account, especially if self-assigned, is highly suspicious as it might indicate an adversary trying to establish persistence in the environment.

**Possible Investigation Steps**

* ***Identify the Source and Context of the Action***:
* Examine the `source.address` field to identify the IP address from which the request originated.
* Check the geographic location (`source.address`) to determine if the access is from an expected or unexpected region.
* Look at the `user_agent.original` field to identify the tool or browser used for this action.
* For example, a user agent like `Mozilla/5.0` might indicate interactive access, whereas `aws-cli` or SDKs suggest scripted activity.
* ***Confirm Root User and Request Details***:
* Validate the root user’s identity through `aws.cloudtrail.user_identity.arn` and ensure this activity aligns with legitimate administrative actions.
* Review `aws.cloudtrail.user_identity.access_key_id` to identify if the action was performed using temporary or permanent credentials. This access key could be used to pivot into other actions.
* ***Analyze the Login Profile Creation***:
* Review the `aws.cloudtrail.request_parameters` and `aws.cloudtrail.response_elements` fields for details of the created login profile.
* For example, confirm the `userName` of the profile and whether `passwordResetRequired` is set to `true`.
* Compare the `@timestamp` of this event with other recent actions by the root account to identify potential privilege escalation or abuse.
* ***Correlate with Other Events***:
* Investigate for related IAM activities, such as:
* `CreateAccessKey` or `AttachUserPolicy` events targeting the root account.
* Unusual data access, privilege escalation, or management console logins.
* Check for any anomalies involving the same `source.address` or `aws.cloudtrail.user_identity.access_key_id` in the environment.
* ***Evaluate Policy and Permissions***:
* Verify the current security policies for the root account:
* Ensure password policies enforce complexity and rotation requirements.
* Check if MFA is enforced on the root account.
* Assess the broader IAM configuration for deviations from least privilege principles.

**False Positive Analysis**

* ***Routine Administrative Tasks***: Adding a login profile might be a legitimate action during certain administrative processes. Verify with the relevant AWS administrators if this event aligns with routine account maintenance or emergency recovery scenarios.
* ***Automation***: If the action is part of an approved automation process (e.g., account recovery workflows), consider excluding these activities from alerting using specific user agents, IP addresses, or session attributes.

**Response and Remediation**

* ***Immediate Access Review***:
* Disable the newly created login profile (`aws iam delete-login-profile`) if it is determined to be unauthorized.
* Rotate or disable the credentials associated with the root account to prevent further abuse.
* ***Enhance Monitoring and Alerts***:
* Enable real-time monitoring and alerting for IAM actions involving the root account.
* Increase the logging verbosity for root account activities.
* ***Review and Update Security Policies***:
* Enforce MFA for all administrative actions, including root account usage.
* Restrict programmatic access to the root account by disabling access keys unless absolutely necessary.
* ***Conduct Post-Incident Analysis***:
* Investigate how the credentials for the root account were compromised or misused.
* Strengthen the security posture by implementing account-specific guardrails and continuous monitoring.

**Additional Resources**

* AWS documentation on [Login Profile Management](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateLoginProfile.md).


## Rule query [_rule_query_4778]

```js
from logs-aws.cloudtrail* metadata _id, _version, _index
| where
    // filter for CloudTrail logs from IAM
    event.dataset == "aws.cloudtrail"
    and event.provider == "iam.amazonaws.com"

    // filter for successful CreateLoginProfile API call
    and event.action == "CreateLoginProfile"
    and event.outcome == "success"

    // filter for Root member account
    and aws.cloudtrail.user_identity.type == "Root"

    // filter for an access key existing which sources from AssumeRoot
    and aws.cloudtrail.user_identity.access_key_id IS NOT NULL

    // filter on the request parameters not including UserName which assumes self-assignment
    and NOT TO_LOWER(aws.cloudtrail.request_parameters) LIKE "*username*"
| keep
    @timestamp,
    aws.cloudtrail.request_parameters,
    aws.cloudtrail.response_elements,
    aws.cloudtrail.user_identity.type,
    aws.cloudtrail.user_identity.arn,
    aws.cloudtrail.user_identity.access_key_id,
    cloud.account.id,
    event.action,
    source.address
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Cloud Accounts
    * ID: T1078.004
    * Reference URL: [https://attack.mitre.org/techniques/T1078/004/](https://attack.mitre.org/techniques/T1078/004/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



