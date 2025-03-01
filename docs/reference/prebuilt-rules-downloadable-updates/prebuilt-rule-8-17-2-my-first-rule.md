---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-2-my-first-rule.html
---

# My First Rule [prebuilt-rule-8-17-2-my-first-rule]

This rule helps you test and practice using alerts with Elastic Security as you get set up. It’s not a sign of threat activity.

**Rule type**: threshold

**Rule indices**:

* auditbeat-*
* filebeat-*
* logs-*
* winlogbeat-*

**Severity**: low

**Risk score**: 21

**Runs every**: 30m

**Searches indices from**: now-35m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 1

**References**:

* [/reference/security/prebuilt-rules/index.md](/reference/prebuilt-rules/index.md)

**Tags**:

* Use Case: Guided Onboarding

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3903]

This is a test alert.

This alert does not show threat activity. Elastic created this alert to help you understand how alerts work.

For normal rules, the Investigation Guide will help analysts investigate alerts.

This alert will show once every 24 hours for each host. It is safe to disable this rule.


## Rule query [_rule_query_4809]

```js
event.kind:event
```


