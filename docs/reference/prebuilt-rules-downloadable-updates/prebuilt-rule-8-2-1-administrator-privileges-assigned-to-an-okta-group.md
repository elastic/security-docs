---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-administrator-privileges-assigned-to-an-okta-group.html
---

# Administrator Privileges Assigned to an Okta Group [prebuilt-rule-8-2-1-administrator-privileges-assigned-to-an-okta-group]

Detects when an administrator role is assigned to an Okta group. An adversary may attempt to assign administrator privileges to an Okta group in order to assign additional permissions to compromised user accounts and maintain access to their target organization.

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

## Investigation guide [_investigation_guide_2020]



## Rule query [_rule_query_2305]

```js
event.dataset:okta.system and event.action:group.privilege.grant
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



