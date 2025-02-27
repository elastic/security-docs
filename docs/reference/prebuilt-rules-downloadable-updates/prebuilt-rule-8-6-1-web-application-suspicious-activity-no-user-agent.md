---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-6-1-web-application-suspicious-activity-no-user-agent.html
---

# Web Application Suspicious Activity: No User Agent [prebuilt-rule-8-6-1-web-application-suspicious-activity-no-user-agent]

A request to a web application server contained no identifying user agent string.

**Rule type**: query

**Rule indices**:

* apm-**-transaction**
* traces-apm*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://en.wikipedia.org/wiki/User_agent](https://en.wikipedia.org/wiki/User_agent)

**Tags**:

* Elastic
* APM

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4649]

```js
url.path:*
```


