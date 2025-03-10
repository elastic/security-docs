---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-cloudtrail-log-created.html
---

# AWS CloudTrail Log Created [aws-cloudtrail-log-created]

Identifies the creation of an AWS log trail that specifies the settings for delivery of log data.

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

* [https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_CreateTrail.html](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_CreateTrail.md)
* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/create-trail.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudtrail/create-trail.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Use Case: Log Auditing
* Tactic: Collection
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_10]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS CloudTrail Log Created**

AWS CloudTrail is a service that enables governance, compliance, and operational and risk auditing of your AWS account. It logs API calls and related events, providing visibility into user activity. Adversaries may create new trails to capture sensitive data or cover their tracks. The detection rule identifies successful trail creation, signaling potential unauthorized activity, aiding in early threat detection.

**Possible investigation steps**

* Review the AWS CloudTrail logs to identify the user or role associated with the CreateTrail event by examining the user identity information in the event logs.
* Check the time and date of the CreateTrail event to determine if it aligns with any known maintenance or administrative activities.
* Investigate the configuration of the newly created trail to understand what specific log data it is set to capture and where it is being delivered.
* Assess whether the trail creation was authorized by cross-referencing with change management records or by contacting relevant personnel.
* Analyze other recent AWS CloudTrail events associated with the same user or role to identify any suspicious or unusual activities that may indicate malicious intent.
* Evaluate the permissions and access policies of the user or role involved in the event to ensure they align with the principle of least privilege.

**False positive analysis**

* Routine administrative actions by authorized personnel can trigger this rule. Regularly review and document legitimate trail creation activities to differentiate them from unauthorized actions.
* Automated processes or scripts that create trails for compliance or monitoring purposes may cause false positives. Identify and whitelist these processes to prevent unnecessary alerts.
* Third-party security tools or services that integrate with AWS and create trails for enhanced logging might be mistaken for suspicious activity. Verify these integrations and exclude them from the rule if they are part of your security strategy.
* Changes in organizational policy or structure that require new trail creation can lead to false positives. Ensure that such changes are communicated to the security team to adjust the rule settings accordingly.

**Response and remediation**

* Immediately review the newly created CloudTrail log to verify its legitimacy. Check the user or service account that initiated the trail creation and confirm if it aligns with expected administrative activities.
* If the trail creation is unauthorized, disable or delete the trail to prevent further data capture by potential adversaries.
* Conduct a thorough audit of recent API calls and user activities associated with the account that created the trail to identify any other suspicious actions or configurations.
* Escalate the incident to the security operations team for further investigation and to determine if additional AWS resources have been compromised.
* Implement additional monitoring and alerting for any future unauthorized CloudTrail modifications or creations to enhance early detection capabilities.
* Review and tighten IAM policies and permissions to ensure that only authorized personnel have the ability to create or modify CloudTrail configurations.
* Consider enabling AWS CloudTrail log file integrity validation to ensure that log files have not been altered or deleted, providing an additional layer of security.


## Setup [_setup_7]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_10]

```js
event.dataset:aws.cloudtrail and event.provider:cloudtrail.amazonaws.com and event.action:CreateTrail and event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Cloud Storage
    * ID: T1530
    * Reference URL: [https://attack.mitre.org/techniques/T1530/](https://attack.mitre.org/techniques/T1530/)



