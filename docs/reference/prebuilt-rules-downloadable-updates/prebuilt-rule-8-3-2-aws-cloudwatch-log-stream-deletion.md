---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-aws-cloudwatch-log-stream-deletion.html
---

# AWS CloudWatch Log Stream Deletion [prebuilt-rule-8-3-2-aws-cloudwatch-log-stream-deletion]

Identifies the deletion of an AWS CloudWatch log stream, which permanently deletes all associated archived log events with the stream.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/logs/delete-log-stream.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/logs/delete-log-stream.md)
* [https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteLogStream.html](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DeleteLogStream.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Log Auditing
* Impact
* has_guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2370]

## Triage and analysis

## Investigating AWS CloudWatch Log Stream Deletion

Amazon CloudWatch is a monitoring and observability service that collects monitoring and operational data in the form of
logs, metrics, and events for resources and applications. This data can be used to detect anomalous behavior in your environments, set alarms, visualize
logs and metrics side by side, take automated actions, troubleshoot issues, and discover insights to keep your
applications running smoothly.

A log stream is a sequence of log events that share the same source. Each separate source of logs in CloudWatch Logs
makes up a separate log stream.

This rule looks for the deletion of a log stream using the API `DeleteLogStream` action. Attackers can do this to cover
their tracks and impact security monitoring that relies on these sources.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate other alerts associated with the user account during the past 48 hours.
- Contact the account and resource owners and confirm whether they are aware of this activity.
- Check if this operation was approved and performed according to the organization's change management policy.
- Considering the source IP address and geolocation of the user who issued the command:
    - Do they look normal for the calling user?
    - If the source is an EC2 IP address, is it associated with an EC2 instance in one of your accounts or is the source
    IP from an EC2 instance that's not under your control?
    - If it is an authorized EC2 instance, is the activity associated with normal behavior for the instance role or roles?
    Are there any other alerts or signs of suspicious activity involving this instance?
- Investigate the deleted log stream's criticality and whether the responsible team is aware of the deletion.
- If you suspect the account has been compromised, scope potentially compromised assets by tracking servers, services,
and data accessed by the account in the last 24 hours.

## False positive analysis

- If this rule is noisy in your environment due to expected activity, consider adding exceptions — preferably with a
combination of user and IP address conditions.

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

## Rule query [_rule_query_2741]

```js
event.dataset:aws.cloudtrail and event.provider:logs.amazonaws.com and event.action:DeleteLogStream and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Data Destruction
    * ID: T1485
    * Reference URL: [https://attack.mitre.org/techniques/T1485/](https://attack.mitre.org/techniques/T1485/)

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



