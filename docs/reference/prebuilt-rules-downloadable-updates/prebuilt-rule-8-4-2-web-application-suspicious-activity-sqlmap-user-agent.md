---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-web-application-suspicious-activity-sqlmap-user-agent.html
---

# Web Application Suspicious Activity: sqlmap User Agent [prebuilt-rule-8-4-2-web-application-suspicious-activity-sqlmap-user-agent]

This is an example of how to detect an unwanted web client user agent. This search matches the user agent for sqlmap 1.3.11, which is a popular FOSS tool for testing web applications for SQL injection vulnerabilities.

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

* [http://sqlmap.org/](http://sqlmap.org/)

**Tags**:

* Elastic
* APM

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3785]

```js
user_agent.original:"sqlmap/1.3.11#stable (http://sqlmap.org)"
```


