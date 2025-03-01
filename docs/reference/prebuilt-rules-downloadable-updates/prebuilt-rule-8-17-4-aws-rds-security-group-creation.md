---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-rds-security-group-creation.html
---

# AWS RDS Security Group Creation [prebuilt-rule-8-17-4-aws-rds-security-group-creation]

Identifies the creation of an Amazon Relational Database Service (RDS) Security group.

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

* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBSecurityGroup.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBSecurityGroup.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS RDS
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4050]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS RDS Security Group Creation**

Amazon RDS Security Groups control access to RDS instances, acting as virtual firewalls. Adversaries may exploit this by creating unauthorized security groups to maintain persistence or exfiltrate data. The detection rule monitors successful creation events of RDS security groups, flagging potential misuse by correlating specific AWS CloudTrail logs, thus aiding in identifying unauthorized access attempts.

**Possible investigation steps**

* Review the AWS CloudTrail logs for the event.action:CreateDBSecurityGroup to identify the user or role responsible for the creation of the RDS security group.
* Check the event.provider:rds.amazonaws.com logs to gather additional context about the RDS instance associated with the newly created security group.
* Investigate the event.outcome:success logs to confirm the successful creation and assess if it aligns with expected administrative activities.
* Analyze the associated AWS account and user activity to determine if there are any anomalies or unauthorized access patterns.
* Cross-reference the security group details with existing security policies to ensure compliance and identify any deviations.
* Evaluate the permissions and rules associated with the new security group to assess potential risks or exposure to sensitive data.

**False positive analysis**

* Routine administrative tasks may trigger the rule when authorized personnel create new RDS security groups for legitimate purposes. To manage this, establish a list of known IP addresses or user accounts that frequently perform these tasks and create exceptions for them.
* Automated deployment tools or scripts that create RDS security groups as part of infrastructure provisioning can lead to false positives. Identify these tools and their associated accounts, then configure the rule to exclude these specific actions.
* Scheduled maintenance or updates that involve creating new security groups might be flagged. Document these scheduled activities and adjust the rule to recognize and exclude them during the specified time frames.
* Testing environments where security groups are frequently created and deleted for development purposes can generate alerts. Implement tagging or naming conventions for test environments and exclude these from the rule’s scope.

**Response and remediation**

* Immediately review the AWS CloudTrail logs to confirm the unauthorized creation of the RDS security group and identify the source IP and user account involved in the action.
* Revoke any unauthorized security group rules associated with the newly created RDS security group to prevent further unauthorized access or data exfiltration.
* Temporarily disable or delete the unauthorized RDS security group to contain the threat and prevent persistence.
* Conduct a thorough audit of all AWS IAM roles and permissions to ensure that only authorized users have the ability to create or modify RDS security groups.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or data have been compromised.
* Implement additional monitoring and alerting for any future RDS security group creation events to quickly detect and respond to similar threats.
* Review and update AWS security policies and access controls to prevent unauthorized security group creation, ensuring alignment with best practices for least privilege.


## Setup [_setup_948]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5067]

```js
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:CreateDBSecurityGroup and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create Account
    * ID: T1136
    * Reference URL: [https://attack.mitre.org/techniques/T1136/](https://attack.mitre.org/techniques/T1136/)

* Sub-technique:

    * Name: Cloud Account
    * ID: T1136.003
    * Reference URL: [https://attack.mitre.org/techniques/T1136/003/](https://attack.mitre.org/techniques/T1136/003/)



