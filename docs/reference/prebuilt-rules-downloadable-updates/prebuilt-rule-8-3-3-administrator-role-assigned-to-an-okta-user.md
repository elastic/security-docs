---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-administrator-role-assigned-to-an-okta-user.html
---

# Administrator Role Assigned to an Okta User [prebuilt-rule-8-3-3-administrator-role-assigned-to-an-okta-user]

Identifies when an administrator role is assigned to an Okta user. An adversary may attempt to assign an administrator role to an Okta user in order to assign additional permissions to a user account and maintain access to their target’s environment.

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

* [https://help.okta.com/en/prod/Content/Topics/Security/administrators-admin-comparison.htm](https://help.okta.com/en/prod/Content/Topics/Security/administrators-admin-comparison.htm)
* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)

**Tags**:

* Elastic
* Okta
* SecOps
* Monitoring
* Continuous Monitoring

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2938]



## Rule query [_rule_query_3359]

```js
event.dataset:okta.system and event.action:user.account.privilege.grant
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)



