---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-attempt-to-deactivate-an-okta-application.html
---

# Attempt to Deactivate an Okta Application [prebuilt-rule-8-3-3-attempt-to-deactivate-an-okta-application]

Detects attempts to deactivate an Okta application. An adversary may attempt to modify, deactivate, or delete an Okta application in order to weaken an organization’s security controls or disrupt their business operations.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://help.okta.com/en/prod/Content/Topics/Apps/Apps_Apps.htm](https://help.okta.com/en/prod/Content/Topics/Apps/Apps_Apps.htm)
* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)

**Tags**:

* Elastic
* Identity
* Okta
* Continuous Monitoring
* SecOps
* Monitoring
* Impact

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2930]



## Rule query [_rule_query_3351]

```js
event.dataset:okta.system and event.action:application.lifecycle.deactivate
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Service Stop
    * ID: T1489
    * Reference URL: [https://attack.mitre.org/techniques/T1489/](https://attack.mitre.org/techniques/T1489/)



