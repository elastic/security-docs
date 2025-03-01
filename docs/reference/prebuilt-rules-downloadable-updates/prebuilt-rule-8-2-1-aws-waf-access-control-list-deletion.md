---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-aws-waf-access-control-list-deletion.html
---

# AWS WAF Access Control List Deletion [prebuilt-rule-8-2-1-aws-waf-access-control-list-deletion]

Identifies the deletion of a specified AWS Web Application Firewall (WAF) access control list.

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

* [https://awscli.amazonaws.com/v2/documentation/api/latest/reference/waf-regional/delete-web-acl.html](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/waf-regional/delete-web-acl.md)
* [https://docs.aws.amazon.com/waf/latest/APIReference/API_wafRegional_DeleteWebACL.html](https://docs.aws.amazon.com/waf/latest/APIReference/API_wafRegional_DeleteWebACL.md)

**Tags**:

* Elastic
* Cloud
* AWS
* Continuous Monitoring
* SecOps
* Network Security

**Version**: 9

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1845]



## Rule query [_rule_query_2135]

```js
event.dataset:aws.cloudtrail and event.action:DeleteWebACL and event.outcome:success
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



