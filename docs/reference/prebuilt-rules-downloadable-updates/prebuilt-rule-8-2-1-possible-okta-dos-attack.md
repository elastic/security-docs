---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-possible-okta-dos-attack.html
---

# Possible Okta DoS Attack [prebuilt-rule-8-2-1-possible-okta-dos-attack]

Detects possible Denial of Service (DoS) attacks against an Okta organization. An adversary may attempt to disrupt an organization’s business operations by performing a DoS attack against its Okta service.

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

## Investigation guide [_investigation_guide_2016]



## Rule query [_rule_query_2301]

```js
event.dataset:okta.system and event.action:(application.integration.rate_limit_exceeded or system.org.rate_limit.warning or system.org.rate_limit.violation or core.concurrency.org.limit.violation)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Network Denial of Service
    * ID: T1498
    * Reference URL: [https://attack.mitre.org/techniques/T1498/](https://attack.mitre.org/techniques/T1498/)

* Technique:

    * Name: Endpoint Denial of Service
    * ID: T1499
    * Reference URL: [https://attack.mitre.org/techniques/T1499/](https://attack.mitre.org/techniques/T1499/)



