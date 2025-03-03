---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-web-application-suspicious-activity-post-request-declined.html
---

# Web Application Suspicious Activity: POST Request Declined [prebuilt-rule-8-4-2-web-application-suspicious-activity-post-request-declined]

A POST request to a web application returned a 403 response, which indicates the web application declined to process the request because the action requested was not allowed.

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

* [https://en.wikipedia.org/wiki/HTTP_403](https://en.wikipedia.org/wiki/HTTP_403)

**Tags**:

* Elastic
* APM

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3783]

```js
http.response.status_code:403 and http.request.method:post
```


