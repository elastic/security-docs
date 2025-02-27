---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-2-multiple-okta-sessions-detected-for-a-single-user.html
---

# Multiple Okta Sessions Detected for a Single User [prebuilt-rule-8-17-2-multiple-okta-sessions-detected-for-a-single-user]

Detects when a user has started multiple Okta sessions with the same user account and different session IDs. This may indicate that an attacker has stolen the user’s session cookie and is using it to access the user’s account from a different location.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

**Runs every**: 30m

**Searches indices from**: now-35m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection](https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Use Case: Identity and Access Audit
* Data Source: Okta
* Tactic: Lateral Movement

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3905]



## Setup [_setup_789]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_4813]

```js
event.dataset:okta.system
    and okta.event_type:user.session.start
    and okta.authentication_context.external_session_id:*
    and not (okta.actor.id: okta* or okta.actor.display_name: okta*)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Web Session Cookie
    * ID: T1550.004
    * Reference URL: [https://attack.mitre.org/techniques/T1550/004/](https://attack.mitre.org/techniques/T1550/004/)



