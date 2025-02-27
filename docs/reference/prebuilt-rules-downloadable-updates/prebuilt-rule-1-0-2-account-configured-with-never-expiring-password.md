---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-account-configured-with-never-expiring-password.html
---

# Account configured with never Expiring Password [prebuilt-rule-1-0-2-account-configured-with-never-expiring-password]

Detects the creation and modification of an account with the "Don’t Expire Password" option enabled. Attackers can abuse this misconfiguration to persist in the domain and maintain long-term access using compromised accounts with this property.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-system.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.cert.ssi.gouv.fr/uploads/guide-ad.html#dont_expire](https://www.cert.ssi.gouv.fr/uploads/guide-ad.md#dont_expire)
* [https://web.archive.org/web/20230329171952/https://blog.menasec.net/2019/02/threat-hunting-26-persistent-password.html](https://web.archive.org/web/20230329171952/https://blog.menasec.net/2019/02/threat-hunting-26-persistent-password.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence
* Active Directory

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1603]

```js
event.action:"modified-user-account" and event.code:"4738" and message:"'Don't Expire Password' - Enabled" and not user.id:"S-1-5-18"
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



