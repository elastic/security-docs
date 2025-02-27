---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-3-external-alerts.html
---

# External Alerts [prebuilt-rule-0-13-3-external-alerts]

Generates a detection alert for each external alert written to the configured indices. Enabling this rule allows you to immediately begin investigating external alerts in the app.

**Rule type**: query

**Rule indices**:

* apm-**-transaction**
* traces-apm*
* auditbeat-*
* filebeat-*
* logs-*
* packetbeat-*
* winlogbeat-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 10000

**References**: None

**Tags**:

* Elastic
* Network
* Windows
* APM
* macOS
* Linux

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1320]

```js
event.kind:alert and not event.module:(endgame or endpoint)
```


