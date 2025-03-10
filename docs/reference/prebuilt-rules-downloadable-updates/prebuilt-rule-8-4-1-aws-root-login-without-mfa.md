---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-aws-root-login-without-mfa.html
---

# AWS Root Login Without MFA [prebuilt-rule-8-4-1-aws-root-login-without-mfa]

Identifies attempts to login to AWS as the root user without using multi-factor authentication (MFA). Amazon AWS best practices indicate that the root user should be protected by MFA.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: high

**Risk score**: 73

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Identity and Access
* Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2606]

## Triage and analysis

## Investigating AWS Root Login Without MFA

Multi-factor authentication (MFA) in AWS is a simple best practice that adds an extra layer of protection on top of your
user name and password. With MFA enabled, when a user signs in to an AWS Management Console, they will be prompted for
their user name and password, as well as for an authentication code from their AWS MFA device. Taken together, these
multiple factors provide increased security for your AWS account settings and resources.

For more information about using MFA in AWS, access the [official documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html).

The AWS root account is the one identity that has complete access to all AWS services and resources in the account,
which is created when the AWS account is created. AWS strongly recommends that you do not use the root user for your
everyday tasks, even the administrative ones. Instead, adhere to the best practice of using the root user only to create
your first IAM user. Then securely lock away the root user credentials and use them to perform only a few account and
service management tasks. Amazon provides a [list of the tasks that require root user](https://docs.aws.amazon.com/general/latest/gr/root-vs-iam.html#aws_tasks-that-require-root).

This rule looks for attempts to log in to AWS as the root user without using multi-factor authentication (MFA), meaning
the account is not secured properly.

### Possible investigation steps

- Investigate other alerts associated with the user account during the past 48 hours.
- Examine whether this activity is common in the environment by looking for past occurrences on your logs.
- Consider the source IP address and geolocation for the calling user who issued the command. Do they look normal for the
  calling user?
- Examine the commands, API calls, and data management actions performed by the account in the last 24 hours.
- Contact the account owner and confirm whether they are aware of this activity.
- If you suspect the account has been compromised, scope potentially compromised assets by tracking access to servers,
services, and data accessed by the account in the last 24 hours.

## False positive analysis

- While this activity is not inherently malicious, the root account must use MFA. The security team should address any
potential benign true positive (B-TP), as this configuration can risk the entire cloud environment.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
    - Identify the account role in the cloud environment.
    - Identify the services or servers involved criticality.
    - Work with your IT team to identify and minimize the impact on users.
    - Identify if the attacker is moving laterally and compromising other accounts, servers, or services.
    - Identify if there are any regulatory or legal ramifications related to this activity.
- Configure multi-factor authentication for the user.
- Follow security best practices [outlined](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/) by AWS.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2992]

```js
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:ConsoleLogin and
  aws.cloudtrail.user_identity.type:Root and
  aws.cloudtrail.console_login.additional_eventdata.mfa_used:false and
  event.outcome:success
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



