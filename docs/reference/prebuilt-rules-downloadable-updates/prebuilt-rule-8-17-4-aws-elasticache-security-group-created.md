---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-elasticache-security-group-created.html
---

# AWS ElastiCache Security Group Created [prebuilt-rule-8-17-4-aws-elasticache-security-group-created]

Identifies when an ElastiCache security group has been created.

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

* [https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateCacheSecurityGroup.html](https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateCacheSecurityGroup.html)

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

## Investigation guide [_investigation_guide_3989]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS ElastiCache Security Group Created**

AWS ElastiCache security groups control access to cache clusters, ensuring only authorized traffic can interact with them. Adversaries might create new security groups to bypass existing restrictions, facilitating unauthorized access or data exfiltration. The detection rule monitors for successful creation events of these groups, signaling potential defense evasion tactics by identifying unusual or unauthorized configurations.

**Possible investigation steps**

* Review the CloudTrail logs for the specific event.action "Create Cache Security Group" to identify the user or role that initiated the creation of the ElastiCache security group.
* Examine the event.provider field to confirm that the event is associated with elasticache.amazonaws.com, ensuring the alert is relevant to ElastiCache services.
* Check the event.outcome field to verify that the security group creation was successful, confirming the alert’s validity.
* Investigate the IAM permissions and roles associated with the user or entity that created the security group to determine if they have legitimate access and reasons for this action.
* Analyze the configuration of the newly created ElastiCache security group to identify any overly permissive rules or unusual configurations that could indicate malicious intent.
* Correlate this event with other recent activities in the AWS account, such as changes to IAM policies or unusual login attempts, to assess if this is part of a broader attack pattern.

**False positive analysis**

* Routine administrative actions by authorized personnel can trigger this rule. Regularly review and document legitimate security group creation activities to differentiate them from suspicious actions.
* Automated processes or scripts that create security groups as part of normal operations may cause false positives. Identify and whitelist these processes to prevent unnecessary alerts.
* Infrastructure as Code (IaC) tools like Terraform or CloudFormation might create security groups during deployments. Ensure these tools and their actions are well-documented and consider excluding their known patterns from triggering alerts.
* Development and testing environments often involve frequent creation and deletion of resources, including security groups. Establish separate monitoring rules or exceptions for these environments to reduce noise.
* Scheduled maintenance or updates that involve security group modifications should be communicated to the security team in advance, allowing them to temporarily adjust monitoring rules or expectations.

**Response and remediation**

* Immediately review the newly created ElastiCache security group to verify its necessity and ensure it aligns with organizational security policies. If unauthorized, proceed to delete the security group to prevent potential misuse.
* Conduct a thorough audit of recent IAM activity to identify any unauthorized access or privilege escalation that may have led to the creation of the security group. Pay special attention to any anomalies in user behavior or access patterns.
* Isolate any affected ElastiCache instances by temporarily restricting access to them until a full assessment is completed. This helps prevent any potential data exfiltration or unauthorized access.
* Notify the security operations team and relevant stakeholders about the incident for further investigation and to ensure awareness across the organization.
* Implement additional monitoring on the AWS account to detect any further unauthorized changes to security groups or other critical configurations, enhancing the detection capabilities for similar threats.
* Review and update IAM policies and permissions to ensure the principle of least privilege is enforced, reducing the risk of unauthorized security group creation in the future.
* If the incident is confirmed as malicious, escalate to the incident response team for a comprehensive investigation and to determine if further actions, such as legal or regulatory reporting, are necessary.


## Setup [_setup_923]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5006]

```js
event.dataset:aws.cloudtrail and event.provider:elasticache.amazonaws.com and event.action:"Create Cache Security Group" and
event.outcome:success
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



