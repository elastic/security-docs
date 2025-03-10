---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-elasticache-security-group-modified-or-deleted.html
---

# AWS ElastiCache Security Group Modified or Deleted [aws-elasticache-security-group-modified-or-deleted]

Identifies when an ElastiCache security group has been modified or deleted.

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

* [https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/Welcome.html](https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/Welcome.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_39]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS ElastiCache Security Group Modified or Deleted**

AWS ElastiCache security groups control inbound and outbound traffic to cache clusters, ensuring only authorized access. Adversaries may modify or delete these groups to bypass security controls, facilitating unauthorized data access or exfiltration. The detection rule monitors specific API actions related to security group changes, flagging successful modifications or deletions as potential defense evasion attempts.

**Possible investigation steps**

* Review the CloudTrail logs for the specific event.provider: elasticache.amazonaws.com to identify the user or role that initiated the security group modification or deletion.
* Examine the event.action field to determine the exact action taken, such as "Delete Cache Security Group" or "Authorize Cache Security Group Ingress", and assess the potential impact on security posture.
* Check the event.outcome field to confirm the success of the action and correlate it with any other suspicious activities in the same timeframe.
* Investigate the source IP address and location associated with the event to determine if it aligns with expected administrative activity.
* Review the AWS IAM policies and permissions associated with the user or role to ensure they are appropriate and have not been overly permissive.
* Assess the affected ElastiCache clusters to determine if any unauthorized access or data exfiltration attempts have occurred following the security group change.

**False positive analysis**

* Routine maintenance activities by authorized personnel can trigger alerts when they modify security groups for legitimate reasons. To manage this, create exceptions for known maintenance windows or specific user actions.
* Automated scripts or tools used for infrastructure management might modify security groups as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts by using specific user or role identifiers.
* Changes made by cloud management platforms or third-party services that integrate with AWS may also result in false positives. Review and whitelist these services if they are verified as non-threatening.
* Regular updates or deployments that require temporary security group modifications can be mistaken for suspicious activity. Document these processes and adjust the detection rule to account for these expected changes.
* Ensure that any changes made by trusted IP addresses or within a specific network range are reviewed and potentially excluded from alerting, as they may represent internal, authorized activities.

**Response and remediation**

* Immediately isolate the affected ElastiCache instance by applying restrictive security group rules to prevent further unauthorized access.
* Review CloudTrail logs to identify any unauthorized API calls related to the security group modifications and determine the source of the changes.
* Revert any unauthorized changes to the ElastiCache security groups by restoring them to their previous state using backups or documented configurations.
* Conduct a thorough investigation to identify any data exfiltration or unauthorized access that may have occurred due to the security group changes.
* Escalate the incident to the security operations team for further analysis and to determine if additional security measures are required.
* Implement additional monitoring and alerting for changes to ElastiCache security groups to ensure rapid detection of similar threats in the future.
* Review and update IAM policies to ensure that only authorized personnel have permissions to modify ElastiCache security groups, reducing the risk of future unauthorized changes.


## Setup [_setup_25]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_40]

```js
event.dataset:aws.cloudtrail and event.provider:elasticache.amazonaws.com and event.action:("Delete Cache Security Group" or
"Authorize Cache Security Group Ingress" or  "Revoke Cache Security Group Ingress" or "AuthorizeCacheSecurityGroupEgress" or
"RevokeCacheSecurityGroupEgress") and event.outcome:success
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

    * Name: Disable or Modify Cloud Firewall
    * ID: T1562.007
    * Reference URL: [https://attack.mitre.org/techniques/T1562/007/](https://attack.mitre.org/techniques/T1562/007/)



