---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-okta-threatinsight-threat-suspected-promotion.html
---

# Okta ThreatInsight Threat Suspected Promotion [prebuilt-rule-8-17-4-okta-threatinsight-threat-suspected-promotion]

Okta ThreatInsight is a feature that provides valuable debug data regarding authentication and authorization processes, which is logged in the system. Within this data, there is a specific field called threat_suspected, which represents Okta’s internal evaluation of the authentication or authorization workflow. When this field is set to True, it suggests the presence of potential credential access techniques, such as password-spraying, brute-forcing, replay attacks, and other similar threats.

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
* [https://help.okta.com/en-us/Content/Topics/Security/threat-insight/configure-threatinsight-system-log.html](https://help.okta.com/en-us/Content/Topics/Security/threat-insight/configure-threatinsight-system-log.md)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Use Case: Identity and Access Audit
* Data Source: Okta
* Resources: Investigation Guide

**Version**: 410

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4282]

**Triage and analysis**

This is a promotion rule for Okta ThreatInsight suspected threat events, which are alertable events per the vendor. Consult vendor documentation on interpreting specific events.


## Setup [_setup_1139]



## Rule query [_rule_query_5280]

```js
event.dataset:okta.system and (event.action:security.threat.detected or okta.debug_context.debug_data.threat_suspected: true)
```


