---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-threat-detected-by-okta-threatinsight.html
---

# Threat Detected by Okta ThreatInsight [prebuilt-rule-8-2-1-threat-detected-by-okta-threatinsight]

Detects when Okta ThreatInsight identifies a request from a malicious IP address. Investigating requests from IP addresses identified as malicious by Okta ThreatInsight can help security teams monitor for and respond to credential based attacks against their organization, such as brute force and password spraying attacks.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)

**Tags**:

* Elastic
* Identity
* Okta
* Continuous Monitoring
* SecOps
* Monitoring

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2019]



## Rule query [_rule_query_2304]

```js
event.dataset:okta.system and event.action:security.threat.detected
```


