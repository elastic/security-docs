---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-signin-single-factor-console-login-with-federated-user.html
---

# AWS Signin Single Factor Console Login with Federated User [prebuilt-rule-8-17-4-aws-signin-single-factor-console-login-with-federated-user]

Identifies when a federated user logs into the AWS Management Console without using multi-factor authentication (MFA). Federated users are typically given temporary credentials to access AWS services. If a federated user logs into the AWS Management Console without using MFA, it may indicate a security risk, as MFA adds an additional layer of security to the authentication process. This could also indicate the abuse of STS tokens to bypass MFA requirements.

**Rule type**: esql

**Rule indices**: None

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://hackingthe.cloud/aws/post_exploitation/create_a_console_session_from_iam_credentials/](https://hackingthe.cloud/aws/post_exploitation/create_a_console_session_from_iam_credentials/)

**Tags**:

* Domain: Cloud
* Data Source: Amazon Web Services
* Data Source: AWS
* Data Source: AWS Sign-In
* Use Case: Threat Detection
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4034]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS Signin Single Factor Console Login with Federated User**

Federated users in AWS are granted temporary credentials to access resources, often without the need for a permanent account. This setup is convenient but can be risky if not properly secured with multi-factor authentication (MFA). Adversaries might exploit this by using stolen or misconfigured credentials to gain unauthorized access. The detection rule identifies instances where federated users log in without MFA, flagging potential security risks by analyzing specific AWS CloudTrail events and dissecting login data to check for the absence of MFA, thus helping to mitigate unauthorized access attempts.

**Possible investigation steps**

* Review the AWS CloudTrail logs to confirm the event details, focusing on the event.provider, event.action, and aws.cloudtrail.user_identity.type fields to ensure the alert corresponds to a federated user login without MFA.
* Identify the federated user involved by examining the aws.cloudtrail.user_identity.arn field to determine which user or service is associated with the login attempt.
* Check the aws.cloudtrail.additional_eventdata field to verify the mfa_used value is "No" and assess if this is expected behavior for the identified user or service.
* Investigate the source IP address and location of the login attempt to determine if it aligns with typical access patterns for the federated user.
* Review recent activity associated with the federated user to identify any unusual or unauthorized actions that may have occurred following the login event.
* Assess the configuration and policies of the Identity Provider (IdP) used for federated access to ensure MFA is enforced and properly configured for all users.

**False positive analysis**

* Federated users with specific roles or permissions may frequently log in without MFA due to operational requirements. Review these roles and consider adding them to an exception list if they are deemed non-threatening.
* Automated processes or scripts using federated credentials might trigger this rule if they are not configured to use MFA. Verify these processes and, if legitimate, exclude them from the rule to prevent unnecessary alerts.
* Temporary testing or development accounts might be set up without MFA for convenience. Ensure these accounts are monitored and, if necessary, excluded from the rule to avoid false positives.
* Third-party integrations or services that rely on federated access without MFA could be flagged. Assess these integrations and whitelist them if they are secure and necessary for business operations.
* Users accessing AWS from secure, controlled environments might not use MFA as part of a risk-based authentication strategy. Evaluate the security of these environments and consider excluding them if they meet your organization’s security standards.

**Response and remediation**

* Immediately revoke the temporary credentials associated with the federated user account to prevent further unauthorized access.
* Conduct a thorough review of AWS CloudTrail logs to identify any suspicious activities or unauthorized access attempts associated with the federated user account.
* Notify the security team and relevant stakeholders about the potential security breach to ensure coordinated response efforts.
* Implement or enforce multi-factor authentication (MFA) for all federated user accounts to enhance security and prevent similar incidents in the future.
* Review and update IAM policies and roles associated with federated users to ensure they follow the principle of least privilege.
* Escalate the incident to the incident response team if any malicious activities are detected, and initiate a full security investigation to assess the impact and scope of the breach.
* Monitor AWS CloudTrail and other relevant logs closely for any further unauthorized access attempts or anomalies related to federated user accounts.


## Rule query [_rule_query_5051]

```js
from logs-aws.cloudtrail-* metadata _id, _version, _index
| where
    event.provider == "signin.amazonaws.com"
    and event.action == "GetSigninToken"
    and aws.cloudtrail.event_type == "AwsConsoleSignIn"
    and aws.cloudtrail.user_identity.type == "FederatedUser"
| dissect aws.cloudtrail.additional_eventdata "{%{?mobile_version_key}=%{mobile_version}, %{?mfa_used_key}=%{mfa_used}}"
| where mfa_used == "No"
| keep @timestamp, event.action, aws.cloudtrail.event_type, aws.cloudtrail.user_identity.type
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Cloud Accounts
    * ID: T1078.004
    * Reference URL: [https://attack.mitre.org/techniques/T1078/004/](https://attack.mitre.org/techniques/T1078/004/)



