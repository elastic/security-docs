---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-route-table-created.html
---

# AWS Route Table Created [prebuilt-rule-8-17-4-aws-route-table-created]

Identifies when an AWS Route Table has been created.

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

* [https://docs.datadoghq.com/security_platform/default_rules/aws-ec2-route-table-modified/](https://docs.datadoghq.com/security_platform/default_rules/aws-ec2-route-table-modified/)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateRoute.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateRoute.md)
* [https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateRouteTable](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateRouteTable)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Data Source: AWS Route53
* Use Case: Network Security Monitoring
* Tactic: Persistence
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic
* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4057]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS Route Table Created**

AWS Route Tables are crucial components in managing network traffic within AWS environments, directing data between subnets and internet gateways. Adversaries may exploit route tables to reroute traffic for data exfiltration or to establish persistence by creating unauthorized routes. The detection rule monitors successful creation events of route tables, flagging potential misuse by correlating specific AWS CloudTrail logs, thus aiding in identifying unauthorized network configuration changes.

**Possible investigation steps**

* Review the AWS CloudTrail logs for the specific event.provider:ec2.amazonaws.com and event.action values (CreateRoute or CreateRouteTable) to identify the user or role that initiated the route table creation.
* Check the event.outcome:success field to confirm the successful creation of the route table and gather additional context such as timestamps and source IP addresses.
* Investigate the associated AWS account and IAM user or role to determine if the action aligns with expected behavior and permissions.
* Examine the newly created route table’s configuration to identify any unauthorized or suspicious routes that could indicate potential misuse or data exfiltration attempts.
* Correlate the event with other network security monitoring data to identify any unusual traffic patterns or anomalies that coincide with the route table creation.
* Assess the environment for any recent changes or incidents that might explain the creation of the route table, such as new deployments or infrastructure modifications.

**False positive analysis**

* Routine infrastructure updates or deployments may trigger route table creation events. To manage this, establish a baseline of expected behavior during scheduled maintenance windows and exclude these from alerts.
* Automated cloud management tools often create route tables as part of their operations. Identify these tools and create exceptions for their known activities to reduce noise.
* Development and testing environments frequently undergo changes, including the creation of route tables. Consider excluding these environments from alerts or applying a different set of monitoring rules.
* Legitimate changes by authorized personnel can be mistaken for suspicious activity. Implement a process to verify and document authorized changes, allowing for quick exclusion of these events from alerts.
* Multi-account AWS setups might have centralized networking teams that create route tables across accounts. Coordinate with these teams to understand their activities and exclude them from triggering alerts.

**Response and remediation**

* Immediately isolate the affected AWS account or VPC to prevent further unauthorized network changes and potential data exfiltration.
* Review the newly created route table and any associated routes to identify unauthorized entries. Remove any routes that are not part of the expected network configuration.
* Conduct a thorough audit of IAM roles and permissions to ensure that only authorized users have the ability to create or modify route tables. Revoke any excessive permissions identified.
* Implement network monitoring to detect unusual traffic patterns that may indicate data exfiltration or other malicious activities.
* Escalate the incident to the security operations team for further investigation and to determine if additional AWS resources have been compromised.
* Review AWS CloudTrail logs for any other suspicious activities around the time of the route table creation to identify potential indicators of compromise.
* Update security policies and procedures to include specific guidelines for monitoring and responding to unauthorized route table modifications, ensuring rapid detection and response in the future.


## Setup [_setup_954]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5074]

```js
event.dataset:aws.cloudtrail and event.provider:ec2.amazonaws.com and event.action:(CreateRoute or CreateRouteTable) and
event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)



