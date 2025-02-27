---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-local-account-tokenfilter-policy-disabled.html
---

# Local Account TokenFilter Policy Disabled [prebuilt-rule-8-4-1-local-account-tokenfilter-policy-disabled]

Identifies registry modification to the LocalAccountTokenFilterPolicy policy. If this value exists (which doesn’t by default) and is set to 1, then remote connections from all local members of Administrators are granted full high-integrity tokens during negotiation.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.stigviewer.com/stig/windows_server_2008_r2_member_server/2014-04-02/finding/V-36439](https://www.stigviewer.com/stig/windows_server_2008_r2_member_server/2014-04-02/finding/V-36439)
* [https://posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167](https://posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167)
* [https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf](https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* Privilege Escalation
* Elastic Endgame

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2961]

```js
registry where registry.path : (
  "HKLM\\*\\LocalAccountTokenFilterPolicy",
  "\\REGISTRY\\MACHINE\\*\\LocalAccountTokenFilterPolicy") and
  registry.data.strings : ("1", "0x00000001")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Valid Accounts
    * ID: T1078
    * Reference URL: [https://attack.mitre.org/techniques/T1078/](https://attack.mitre.org/techniques/T1078/)

* Sub-technique:

    * Name: Local Accounts
    * ID: T1078.003
    * Reference URL: [https://attack.mitre.org/techniques/T1078/003/](https://attack.mitre.org/techniques/T1078/003/)



