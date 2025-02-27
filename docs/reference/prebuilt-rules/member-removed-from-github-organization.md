---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/member-removed-from-github-organization.html
---

# Member Removed From GitHub Organization [member-removed-from-github-organization]

A member was removed or their invitation to join was removed from a GitHub Organization.

**Rule type**: eql

**Rule indices**:

* logs-github.audit-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Cloud
* Use Case: Threat Detection
* Use Case: UEBA
* Tactic: Impact
* Rule Type: BBR
* Data Source: Github

**Version**: 204

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_537]

```js
configuration where event.dataset == "github.audit" and event.action == "org.remove_member"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Account Access Removal
    * ID: T1531
    * Reference URL: [https://attack.mitre.org/techniques/T1531/](https://attack.mitre.org/techniques/T1531/)



