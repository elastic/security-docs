---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-aws-execution-via-system-manager.html
---

# AWS Execution via System Manager [prebuilt-rule-8-3-2-aws-execution-via-system-manager]

Identifies the execution of commands and scripts via System Manager. Execution methods such as RunShellScript, RunPowerShellScript, and alike can be abused by an authenticated attacker to install a backdoor or to interact with a compromised instance via reverse-shell using system only commands.

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

* [https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-plugins.html](https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-plugins.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Log Auditing
* Initial Access
* has_guide

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2373]

## Triage and analysis

## Investigating AWS Execution via System Manager

Amazon EC2 Systems Manager is a management service designed to help users automatically collect software inventory, apply
operating system patches, create system images, and configure Windows and Linux operating systems.

This rule looks for the execution of commands and scripts using System Manager. Note that the actual contents of these
scripts and commands are not included in the event, so analysts must gain visibility using an host-level security product.

### Possible investigation steps

- Identify the user account that performed the action and whether it should perform this kind of action.
- Investigate other alerts associated with the user account during the past 48 hours.
- Validate that the activity is not related to planned patches, updates, network administrator activity, or legitimate
software installations.
- Investigate the commands or scripts using host-level visibility.
- Considering the source IP address and geolocation of the user who issued the command:
    - Do they look normal for the calling user?
    - If the source is an EC2 IP address, is it associated with an EC2 instance in one of your accounts or is the source
    IP from an EC2 instance that's not under your control?
    - If it is an authorized EC2 instance, is the activity associated with normal behavior for the instance role or roles?
    Are there any other alerts or signs of suspicious activity involving this instance?
- Assess whether this behavior is prevalent in the environment by looking for similar occurrences involving other users.
- Contact the account owner and confirm whether they are aware of this activity.
- Check if this operation was approved and performed according to the organization's change management policy.
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

## Rule query [_rule_query_2744]

```js
event.dataset:aws.cloudtrail and event.provider:ssm.amazonaws.com and event.action:SendCommand and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Link
    * ID: T1566.002
    * Reference URL: [https://attack.mitre.org/techniques/T1566/002/](https://attack.mitre.org/techniques/T1566/002/)



