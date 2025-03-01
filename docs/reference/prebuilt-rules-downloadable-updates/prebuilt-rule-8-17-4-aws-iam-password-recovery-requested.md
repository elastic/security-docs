---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-iam-password-recovery-requested.html
---

# AWS IAM Password Recovery Requested [prebuilt-rule-8-17-4-aws-iam-password-recovery-requested]

Identifies AWS IAM password recovery requests. An adversary may attempt to gain unauthorized AWS access by abusing password recovery mechanisms.

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

* [https://www.cadosecurity.com/an-ongoing-aws-phishing-campaign/](https://www.cadosecurity.com/an-ongoing-aws-phishing-campaign/)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS Signin
* Use Case: Identity and Access Audit
* Tactic: Initial Access
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4033]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS IAM Password Recovery Requested**

AWS Identity and Access Management (IAM) facilitates secure access control to AWS resources. Password recovery requests are legitimate processes for users to regain access. However, adversaries may exploit this by initiating unauthorized recovery attempts to gain access. The detection rule monitors successful password recovery requests within AWS CloudTrail logs, focusing on initial access tactics, to identify potential misuse and unauthorized access attempts.

**Possible investigation steps**

* Review the AWS CloudTrail logs for the specific event.action:PasswordRecoveryRequested to identify the user account involved in the password recovery request.
* Check the event.provider:signin.amazonaws.com logs to determine the source IP address and geolocation associated with the password recovery request to assess if it aligns with known user activity.
* Investigate the event.outcome:success logs to confirm if the password recovery was completed and if there were any subsequent successful logins from the same or different IP addresses.
* Analyze the user account’s recent activity and permissions to identify any unusual or unauthorized actions that may indicate compromise.
* Cross-reference the event with any other security alerts or incidents involving the same user account to identify potential patterns or coordinated attacks.
* Contact the user associated with the password recovery request to verify if they initiated the request and to ensure their account security.

**False positive analysis**

* Routine password recovery by legitimate users can trigger this rule. To manage this, identify users who frequently request password recovery and consider adding them to an exception list if their behavior is verified as non-threatening.
* Automated password recovery processes used by internal IT support or helpdesk teams may also cause false positives. Coordinate with these teams to understand their workflows and exclude their activities from triggering alerts.
* Users with known issues accessing their accounts due to technical problems might repeatedly request password recovery. Monitor these cases and exclude them once confirmed as non-malicious.
* Scheduled security drills or training exercises that involve password recovery can generate alerts. Ensure these activities are documented and excluded from the rule to prevent unnecessary alerts.

**Response and remediation**

* Immediately verify the legitimacy of the password recovery request by contacting the user associated with the request. Ensure they initiated the recovery process and are aware of the request.
* Temporarily disable the affected IAM user account to prevent any unauthorized access until the situation is fully assessed and resolved.
* Review AWS CloudTrail logs for any additional suspicious activities associated with the IAM user account, such as unusual login attempts or changes to permissions, to identify potential compromise.
* If unauthorized access is confirmed, reset the IAM user’s password and any associated access keys. Ensure the new credentials are communicated securely to the legitimate user.
* Implement multi-factor authentication (MFA) for the affected IAM user account to enhance security and prevent future unauthorized access attempts.
* Escalate the incident to the security operations team for further investigation and to determine if additional accounts or resources have been compromised.
* Update and enhance monitoring rules to detect similar unauthorized password recovery attempts in the future, ensuring timely alerts and responses.


## Setup [_setup_944]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5050]

```js
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:PasswordRecoveryRequested and event.outcome:success
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



