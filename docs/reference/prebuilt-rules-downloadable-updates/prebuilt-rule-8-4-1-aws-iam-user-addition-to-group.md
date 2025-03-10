---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-aws-iam-user-addition-to-group.html
---

# AWS IAM User Addition to Group [prebuilt-rule-8-4-1-aws-iam-user-addition-to-group]

Identifies the addition of a user to a specified group in AWS Identity and Access Management (IAM).

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: low

**Risk score**: 21

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_AddUserToGroup.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AddUserToGroup.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Identity and Access
* Credential Access
* Persistence
* Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2587]

## Triage and analysis

## Investigating AWS IAM User Addition to Group

AWS Identity and Access Management (IAM) provides fine-grained access control across all of AWS. With IAM, you can specify
who can access which services and resources, and under which conditions. With IAM policies, you manage permissions to
your workforce and systems to ensure least-privilege permissions.

This rule looks for the addition of users to a specified user group.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate other alerts associated with the user account during the past 48 hours.
- Contact the account and resource owners and confirm whether they are aware of this activity.
- Check if this operation was approved and performed according to the organization's change management policy.
- If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services,
and data accessed by the account in the last 24 hours.

## False positive analysis

- False positives may occur due to the intended usage of the service. Tuning is needed in order to have higher
confidence. Consider adding exceptions — preferably with a combination of user agent and IP address conditions — to
reduce noise from onboarding processes and administrator activities.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Disable or limit the account during the investigation and response.
- Identify the possible impact of the incident and prioritize accordingly; the following actions can help you gain context:
    - Identify the account role in the cloud environment.
    - Assess the criticality of affected services and servers.
    - Work with your IT team to identify and minimize the impact on users.
    - Identify if the attacker is moving laterally and compromising other accounts, servers, or services.
    - Identify any regulatory or legal ramifications related to this activity.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are
identified. Reset passwords or delete API keys as needed to revoke the attacker's access to the environment. Work with
your IT teams to minimize the impact on business operations during these actions.
- Check if unauthorized new users were created, remove unauthorized new accounts, and request password resets for other
IAM users.
- Consider enabling multi-factor authentication for users.
- Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
- Implement security best practices [outlined](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/) by AWS.
- Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2978]

```js
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:AddUserToGroup and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



