---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-aws-management-console-root-login.html
---

# AWS Management Console Root Login [prebuilt-rule-8-4-1-aws-management-console-root-login]

Identifies a successful login to the AWS Management Console by the Root user.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: medium

**Risk score**: 47

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

## Investigation guide [_investigation_guide_2599]

## Triage and analysis

## Investigating AWS Management Console Root Login

The AWS root account is the one identity that has complete access to all AWS services and resources in the account,
which is created when the AWS account is created. AWS strongly recommends that you do not use the root user for your
everyday tasks, even the administrative ones. Instead, adhere to the best practice of using the root user only to create
your first IAM user. Then securely lock away the root user credentials and use them to perform only a few account and
service management tasks. AWS provides a [list of the tasks that require root user](https://docs.aws.amazon.com/general/latest/gr/root-vs-iam.html#aws_tasks-that-require-root).

This rule looks for attempts to log in to the AWS Management Console as the root user.

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

- The alert can be dismissed if this operation is done under change management and approved according to the
organization's policy for performing a task that needs this privilege level.

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

## Rule query [_rule_query_2990]

```js
event.dataset:aws.cloudtrail and event.provider:signin.amazonaws.com and event.action:ConsoleLogin and aws.cloudtrail.user_identity.type:Root and event.outcome:success
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

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)



