---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-krbtgt-delegation-backdoor.html
---

# KRBTGT Delegation Backdoor [prebuilt-rule-8-7-1-krbtgt-delegation-backdoor]

Identifies the modification of the msDS-AllowedToDelegateTo attribute to KRBTGT. Attackers can use this technique to maintain persistence to the domain by having the ability to request tickets for the KRBTGT service.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-system.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://skyblue.team/posts/delegate-krbtgt](https://skyblue.team/posts/delegate-krbtgt)
* [https://github.com/atc-project/atomic-threat-coverage/blob/master/Atomic_Threat_Coverage/Logging_Policies/LP_0026_windows_audit_user_account_management.md](https://github.com/atc-project/atomic-threat-coverage/blob/master/Atomic_Threat_Coverage/Logging_Policies/LP_0026_windows_audit_user_account_management.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence
* Active Directory

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3875]



## Rule query [_rule_query_4760]

```js
event.action:modified-user-account and event.code:4738 and winlog.event_data.AllowedToDelegateTo:*krbtgt*
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

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Steal or Forge Kerberos Tickets
    * ID: T1558
    * Reference URL: [https://attack.mitre.org/techniques/T1558/](https://attack.mitre.org/techniques/T1558/)



