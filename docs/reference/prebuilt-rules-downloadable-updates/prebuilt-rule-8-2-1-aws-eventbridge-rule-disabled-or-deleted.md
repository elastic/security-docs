---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-eventbridge-rule-disabled-or-deleted.html
---

# AWS EventBridge Rule Disabled or Deleted [prebuilt-rule-8-2-1-aws-eventbridge-rule-disabled-or-deleted]

Identifies when a user has disabled or deleted an EventBridge rule. This activity can result in an unintended loss of visibility in applications or a break in the flow with other AWS services.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-20m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DeleteRule.html](https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DeleteRule.html)
* [https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DisableRule.html](https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DisableRule.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Monitoring
* Impact

**Version**: 5

**Rule authors**:

* Austin Songer

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1852]



## Rule query [_rule_query_2142]

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



