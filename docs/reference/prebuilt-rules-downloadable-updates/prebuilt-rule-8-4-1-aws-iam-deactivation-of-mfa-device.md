---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-aws-iam-deactivation-of-mfa-device.html
---

# AWS IAM Deactivation of MFA Device [prebuilt-rule-8-4-1-aws-iam-deactivation-of-mfa-device]

Identifies the deactivation of a specified multi-factor authentication (MFA) device and removes it from association with the user name for which it was originally enabled. In AWS Identity and Access Management (IAM), a device must be deactivated before it can be deleted.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/deactivate-mfa-device.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/iam/deactivate-mfa-device.md)
* [https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeactivateMFADevice.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeactivateMFADevice.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Monitoring
* Investigation Guide

**Version**: 103

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2598]

## Triage and analysis

## Investigating AWS IAM Deactivation of MFA Device

Multi-factor authentication (MFA) in AWS is a simple best practice that adds an extra layer of protection on top of your
user name and password. With MFA enabled, when a user signs in to an AWS Management Console, they will be prompted for
their user name and password (the first factor—what they know), as well as for an authentication code from their AWS MFA
device (the second factor—what they have). Taken together, these multiple factors provide increased security for your
AWS account settings and resources.

For more information about using MFA in AWS, access the [official documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html).

This rule looks for the deactivation or deletion of AWS MFA devices. These modifications weaken account security and can
lead to the compromise of accounts and other assets.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate other alerts associated with the user account during the past 48 hours.
- Contact the account and resource owners and confirm whether they are aware of this activity.
- Check if this operation was approved and performed according to the organization's change management policy.
- If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services,
and data accessed by the account in the last 24 hours.

## False positive analysis

- While this activity can be done by administrators, all users must use MFA. The security team should address any
potential benign true positive (B-TP), as this configuration can risk the user and domain.

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
- Reactivate multi-factor authentication for the user.
- Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
- Implement security best practices [outlined](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/) by AWS.
- Determine the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2989]

```js
event.dataset:aws.cloudtrail and event.provider:iam.amazonaws.com and event.action:(DeactivateMFADevice or DeleteVirtualMFADevice) and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Account Access Removal
    * ID: T1531
    * Reference URL: [https://attack.mitre.org/techniques/T1531/](https://attack.mitre.org/techniques/T1531/)



