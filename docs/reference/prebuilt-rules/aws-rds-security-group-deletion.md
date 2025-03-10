---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-rds-security-group-deletion.html
---

# AWS RDS Security Group Deletion [aws-rds-security-group-deletion]

Identifies the deletion of an Amazon Relational Database Service (RDS) Security group.

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

* [https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBSecurityGroup.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBSecurityGroup.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS RDS
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_74]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS RDS Security Group Deletion**

Amazon RDS Security Groups control access to RDS instances, acting as a virtual firewall. Adversaries may delete these groups to disrupt database access or cover their tracks. The detection rule monitors AWS CloudTrail logs for successful deletion events of RDS Security Groups, signaling potential unauthorized activity. This helps security analysts quickly identify and respond to suspicious deletions.

**Possible investigation steps**

* Review the AWS CloudTrail logs to confirm the event details, focusing on the event.provider:rds.amazonaws.com and event.action:DeleteDBSecurityGroup fields to ensure the deletion event is accurately captured.
* Identify the user or role associated with the event by examining the user identity information in the CloudTrail logs to determine if the action was performed by an authorized entity.
* Check the event time and correlate it with other security events or alerts to identify any suspicious activity patterns or sequences that might indicate a broader attack.
* Investigate the context of the deletion by reviewing recent changes or activities in the AWS account, such as modifications to IAM policies or unusual login attempts, to assess if the deletion is part of a larger unauthorized access attempt.
* Contact the relevant database or cloud infrastructure team to verify if the deletion was intentional and authorized, ensuring that it aligns with any ongoing maintenance or decommissioning activities.

**False positive analysis**

* Routine maintenance activities by authorized personnel may trigger the rule. To manage this, create exceptions for known maintenance windows or specific user accounts that regularly perform these tasks.
* Automated scripts or tools used for infrastructure management might delete security groups as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts by using specific identifiers or tags.
* Changes in security group configurations during scheduled updates or migrations can result in deletions. Document these events and adjust the detection rule to ignore deletions during these planned activities.
* Testing environments often involve frequent creation and deletion of resources, including security groups. Exclude these environments from monitoring by using environment-specific tags or identifiers.

**Response and remediation**

* Immediately isolate the affected RDS instance by modifying its security group settings to restrict all inbound and outbound traffic, preventing further unauthorized access.
* Review AWS CloudTrail logs to identify the source of the deletion request, including the IAM user or role involved, and assess whether the credentials have been compromised.
* Recreate the deleted RDS Security Group with the appropriate rules and reassign it to the affected RDS instance to restore normal operations.
* Conduct a thorough audit of IAM permissions to ensure that only authorized personnel have the ability to delete RDS Security Groups, and revoke any unnecessary permissions.
* Implement multi-factor authentication (MFA) for all IAM users with permissions to modify RDS Security Groups to enhance security and prevent unauthorized changes.
* Escalate the incident to the security operations team for further investigation and to determine if additional systems or data have been affected.
* Update incident response plans and security policies based on the findings to prevent similar incidents in the future and improve overall cloud security posture.


## Setup [_setup_42]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_78]

```js
event.dataset:aws.cloudtrail and event.provider:rds.amazonaws.com and event.action:DeleteDBSecurityGroup and event.outcome:success
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



