---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-kerberos-cached-credentials-dumping.html
---

# Kerberos Cached Credentials Dumping [prebuilt-rule-0-14-2-kerberos-cached-credentials-dumping]

Identifies the use of the Kerberos credential cache (kcc) utility to dump locally cached Kerberos tickets.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/EmpireProject/EmPyre/blob/master/lib/modules/collection/osx/kerberosdump.py](https://github.com/EmpireProject/EmPyre/blob/master/lib/modules/collection/osx/kerberosdump.py)
* [https://opensource.apple.com/source/Heimdal/Heimdal-323.12/kuser/kcc-commands.in.auto.html](https://opensource.apple.com/source/Heimdal/Heimdal-323.12/kuser/kcc-commands.in.auto.md)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Credential Access

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1408]

```js
event.category:process and event.type:(start or process_started) and
  process.name:kcc and
  process.args:copy_cred_cache
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Technique:

    * Name: Steal or Forge Kerberos Tickets
    * ID: T1558
    * Reference URL: [https://attack.mitre.org/techniques/T1558/](https://attack.mitre.org/techniques/T1558/)

* Sub-technique:

    * Name: Kerberoasting
    * ID: T1558.003
    * Reference URL: [https://attack.mitre.org/techniques/T1558/003/](https://attack.mitre.org/techniques/T1558/003/)



