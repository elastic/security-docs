---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-aws-vpc-flow-logs-deletion.html
---

# AWS VPC Flow Logs Deletion [prebuilt-rule-8-3-2-aws-vpc-flow-logs-deletion]

Identifies the deletion of one or more flow logs in AWS Elastic Compute Cloud (EC2). An adversary may delete flow logs in an attempt to evade defenses.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-flow-logs.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-flow-logs.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Log Auditing
* has_guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2366]

## Triage and analysis

## Investigating AWS VPC Flow Logs Deletion

VPC Flow Logs is an AWS feature that enables you to capture information about the IP traffic going to and from network
interfaces in your virtual private cloud (VPC). Flow log data can be published to Amazon CloudWatch Logs or Amazon S3.

This rule identifies the deletion of VPC flow logs using the API `DeleteFlowLogs` action. Attackers can do this to cover
their tracks and impact security monitoring that relies on this source.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate other alerts associated with the user account during the past 48 hours.
- Contact the account and resource owners and confirm whether they are aware of this activity.
- Check if this operation was approved and performed according to the organization's change management policy.
- Considering the source IP address and geolocation of the user who issued the command:
    - Do they look normal for the user?
    - If the source is an EC2 IP address, is it associated with an EC2 instance in one of your accounts or is the source
    IP from an EC2 instance that's not under your control?
    - If it is an authorized EC2 instance, is the activity associated with normal behavior for the instance role or roles?
    Are there any other alerts or signs of suspicious activity involving this instance?
- If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services,
and data accessed by the account in the last 24 hours.

## False positive analysis

- If this rule is noisy in your environment due to expected activity, consider adding exceptions — preferably with a
combination of user and IP address conditions.
- Administrators may rotate these logs after a certain period as part of their retention policy or after importing them
to a SIEM.

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
- Check if unauthorized new users were created, remove unauthorized new accounts, and request password resets for other IAM users.
- Consider enabling multi-factor authentication for users.
- Review the permissions assigned to the implicated user to ensure that the least privilege principle is being followed.
- Implement security best practices [outlined](https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/) by AWS.
- Take the actions needed to return affected systems, data, or services to their normal operational levels.
- Identify the initial vector abused by the attacker and take action to prevent reinfection via the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the
mean time to respond (MTTR).

## Rule query [_rule_query_2737]

```js
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:DeleteFlowLogs and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



