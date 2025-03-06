---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-waf-rule-or-rule-group-deletion.html
---

# AWS WAF Rule or Rule Group Deletion [prebuilt-rule-8-2-1-aws-waf-rule-or-rule-group-deletion]

Identifies the deletion of a specified AWS Web Application Firewall (WAF) rule or rule group.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-aws*

**Severity**: medium

**Risk score**: 47

**Runs every**: 10m

**Searches indices from**: now-60m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/waf/delete-rule-group.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/waf/delete-rule-group.html)
* [https://docs.aws.amazon.com/waf/latest/APIReference/API_waf_DeleteRuleGroup.html](https://docs.aws.amazon.com/waf/latest/APIReference/API_waf_DeleteRuleGroup.html)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Network Security

**Version**: 10

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1846]



## Rule query [_rule_query_2136]

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



