---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/aws-waf-rule-or-rule-group-deletion.html
---

# AWS WAF Rule or Rule Group Deletion [aws-waf-rule-or-rule-group-deletion]

Identifies the deletion of a specified AWS Web Application Firewall (WAF) rule or rule group.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/waf/delete-rule-group.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/waf/delete-rule-group.md)
* [https://docs.aws.amazon.com/waf/latest/APIReference/API_waf_DeleteRuleGroup.html](https://docs.aws.amazon.com/waf/latest/APIReference/API_waf_DeleteRuleGroup.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Use Case: Network Security Monitoring
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_109]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS WAF Rule or Rule Group Deletion**

AWS Web Application Firewall (WAF) protects web applications by filtering and monitoring HTTP requests. Adversaries may delete WAF rules or groups to disable security measures, facilitating attacks like SQL injection or cross-site scripting. The detection rule monitors AWS CloudTrail logs for successful deletion actions, signaling potential defense evasion attempts by identifying unauthorized or suspicious deletions.

**Possible investigation steps**

* Review the AWS CloudTrail logs to identify the user or role associated with the deletion action by examining the userIdentity field.
* Check the event.time field in the CloudTrail logs to determine when the deletion occurred and correlate it with any other suspicious activities around the same time.
* Investigate the source IP address and user agent from the CloudTrail logs to assess if the request originated from a known or expected location and device.
* Verify if the deleted WAF rule or rule group was part of a critical security configuration by reviewing the AWS WAF setup and any associated documentation.
* Contact the user or team responsible for AWS WAF management to confirm if the deletion was authorized and understand the rationale behind it.
* Examine any recent changes in IAM policies or permissions that might have allowed unauthorized users to perform the deletion action.

**False positive analysis**

* Routine maintenance or updates by authorized personnel can trigger rule deletions. Verify if the deletion aligns with scheduled maintenance activities and consider excluding these events from alerts.
* Automated scripts or tools used for infrastructure management might delete and recreate WAF rules as part of their normal operation. Identify these scripts and whitelist their actions to prevent unnecessary alerts.
* Changes in security policies or architecture might necessitate the removal of certain WAF rules. Ensure that such changes are documented and approved, and exclude these documented actions from triggering alerts.
* Temporary rule deletions for testing purposes by security teams can be mistaken for malicious activity. Coordinate with the security team to log these activities and exclude them from detection rules.
* Ensure that IAM roles or users with permissions to delete WAF rules are reviewed regularly. Exclude actions performed by trusted roles or users after confirming their legitimacy.

**Response and remediation**

* Immediately review AWS CloudTrail logs to confirm the unauthorized deletion of WAF rules or rule groups and identify the source of the action, including the IAM user or role involved.
* Reapply the deleted WAF rules or rule groups to restore the intended security posture and prevent potential attacks such as SQL injection or cross-site scripting.
* Temporarily restrict or revoke permissions for the identified IAM user or role to prevent further unauthorized actions until a thorough investigation is completed.
* Conduct a security review of the affected AWS environment to identify any other potential security gaps or unauthorized changes that may have occurred.
* Notify the security operations team and relevant stakeholders about the incident for awareness and further investigation.
* Implement additional monitoring and alerting for AWS WAF configuration changes to detect and respond to similar unauthorized actions promptly in the future.
* Consider enabling AWS Config rules to continuously monitor and enforce compliance with WAF configurations, ensuring any unauthorized changes are automatically flagged.


## Setup [_setup_61]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_113]

```js
event.dataset:aws.cloudtrail and event.provider:(waf.amazonaws.com or waf-regional.amazonaws.com or wafv2.amazonaws.com) and event.action:(DeleteRule or DeleteRuleGroup) and event.outcome:success
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



