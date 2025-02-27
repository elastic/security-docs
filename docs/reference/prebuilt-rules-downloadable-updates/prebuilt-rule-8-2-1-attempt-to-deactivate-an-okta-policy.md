---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-attempt-to-deactivate-an-okta-policy.html
---

# Attempt to Deactivate an Okta Policy [prebuilt-rule-8-2-1-attempt-to-deactivate-an-okta-policy]

Detects attempts to deactivate an Okta policy. An adversary may attempt to deactivate an Okta policy in order to weaken an organization’s security controls. For example, an adversary may attempt to deactivate an Okta multi-factor authentication (MFA) policy in order to weaken the authentication requirements for user accounts.

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

* [https://help.okta.com/en/prod/Content/Topics/Security/Security_Policies.htm](https://help.okta.com/en/prod/Content/Topics/Security/Security_Policies.htm)
* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)

**Tags**:

* Elastic
* Identity
* Okta
* Continuous Monitoring
* SecOps
* Monitoring
* Defense Evasion

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2004]



## Rule query [_rule_query_2289]

```js
event.dataset:okta.system and event.action:policy.lifecycle.deactivate
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Cloud Firewall
    * ID: T1562.007
    * Reference URL: [https://attack.mitre.org/techniques/T1562/007/](https://attack.mitre.org/techniques/T1562/007/)



