---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-aws-eventbridge-rule-disabled-or-deleted.html
---

# AWS EventBridge Rule Disabled or Deleted [prebuilt-rule-8-17-4-aws-eventbridge-rule-disabled-or-deleted]

Identifies when a user has disabled or deleted an EventBridge rule. This activity can result in an unintended loss of visibility in applications or a break in the flow with other AWS services.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws.cloudtrail-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-20m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DeleteRule.html](https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DeleteRule.md)
* [https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DisableRule.html](https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DisableRule.md)

**Tags**:

* Domain: Cloud
* Data Source: AWS
* Data Source: Amazon Web Services
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4020]

**Triage and analysis**

[TBC: QUOTE]
**Investigating AWS EventBridge Rule Disabled or Deleted**

AWS EventBridge is a serverless event bus service that enables applications to respond to changes in data. Disabling or deleting rules can disrupt event-driven workflows, potentially masking malicious activities. Adversaries might exploit this by halting security alerts or data flows. The detection rule monitors successful disable or delete actions on EventBridge rules, flagging potential misuse that could impact system visibility and integrity.

**Possible investigation steps**

* Review the CloudTrail logs to identify the user or role associated with the DeleteRule or DisableRule action by examining the user identity information in the event logs.
* Check the event time and correlate it with other activities in the AWS account to determine if there are any related suspicious actions or patterns.
* Investigate the specific EventBridge rule that was disabled or deleted to understand its purpose and the potential impact on workflows or security monitoring.
* Assess the permissions and roles of the user who performed the action to determine if they had legitimate access and reasons for modifying the EventBridge rule.
* Look for any recent changes in IAM policies or roles that might have granted new permissions to the user or role involved in the action.
* Contact the user or team responsible for the action to verify if the change was intentional and authorized, and document their response for future reference.

**False positive analysis**

* Routine maintenance or updates by administrators can lead to the disabling or deletion of EventBridge rules. To manage this, create exceptions for known maintenance windows or specific user actions that are documented and approved.
* Automated scripts or tools used for infrastructure management might disable or delete rules as part of their normal operation. Identify these scripts and exclude their actions from triggering alerts by using specific user or role identifiers.
* Testing environments often involve frequent changes to EventBridge rules, including disabling or deleting them. Exclude actions within these environments by filtering based on environment tags or specific resource identifiers.
* Scheduled tasks that involve disabling rules temporarily for performance reasons can be a source of false positives. Document these schedules and configure the detection rule to ignore actions during these periods.
* Changes made by trusted third-party services or integrations that manage EventBridge rules should be reviewed and, if deemed non-threatening, excluded by identifying the service accounts or API keys used.

**Response and remediation**

* Immediately re-enable or recreate the disabled or deleted EventBridge rule to restore the intended event-driven workflows and ensure continuity of operations.
* Conduct a review of CloudTrail logs to identify the user or service account responsible for the action, and verify if the action was authorized and legitimate.
* If unauthorized activity is detected, revoke access for the compromised account and initiate a password reset or key rotation for the affected credentials.
* Notify the security operations team to assess the potential impact on system visibility and integrity, and to determine if further investigation is required.
* Implement additional monitoring and alerting for changes to EventBridge rules to detect similar activities in the future.
* Escalate the incident to the incident response team if there is evidence of malicious intent or if the activity aligns with known threat patterns, such as those described in MITRE ATT&CK technique T1489 (Service Stop).
* Review and update IAM policies to ensure that only authorized users have the necessary permissions to modify EventBridge rules, reducing the risk of unauthorized changes.


## Setup [_setup_934]

The AWS Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5037]

```js
event.dataset:aws.cloudtrail and event.provider:eventbridge.amazonaws.com and event.action:(DeleteRule or DisableRule) and
event.outcome:success
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Service Stop
    * ID: T1489
    * Reference URL: [https://attack.mitre.org/techniques/T1489/](https://attack.mitre.org/techniques/T1489/)



