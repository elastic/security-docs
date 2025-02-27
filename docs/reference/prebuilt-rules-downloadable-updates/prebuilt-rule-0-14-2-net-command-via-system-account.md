---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-net-command-via-system-account.html
---

# Net command via SYSTEM account [prebuilt-rule-0-14-2-net-command-via-system-account]

Identifies the SYSTEM account using an account discovery utility. This could be a sign of discovery activity after an adversary has achieved privilege escalation.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Discovery

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1451]

```js
process where event.type in ("start", "process_started") and
  user.id in ("S-1-5-18", "S-1-5-19", "S-1-5-20") and
  process.name : "whoami.exe" or
  (process.name : "net1.exe" and not process.parent.name : "net.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Owner/User Discovery
    * ID: T1033
    * Reference URL: [https://attack.mitre.org/techniques/T1033/](https://attack.mitre.org/techniques/T1033/)



