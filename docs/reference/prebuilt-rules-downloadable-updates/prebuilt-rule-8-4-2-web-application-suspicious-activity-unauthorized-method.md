---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-web-application-suspicious-activity-unauthorized-method.html
---

# Web Application Suspicious Activity: Unauthorized Method [prebuilt-rule-8-4-2-web-application-suspicious-activity-unauthorized-method]

A request to a web application returned a 405 response, which indicates the web application declined to process the request because the HTTP method is not allowed for the resource.

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

* [https://en.wikipedia.org/wiki/HTTP_405](https://en.wikipedia.org/wiki/HTTP_405)

**Tags**:

* Elastic
* APM

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3784]

```js
http.response.status_code:405
```


