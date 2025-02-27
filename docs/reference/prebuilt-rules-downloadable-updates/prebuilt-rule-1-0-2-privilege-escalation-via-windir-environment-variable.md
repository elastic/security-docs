---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-privilege-escalation-via-windir-environment-variable.html
---

# Privilege Escalation via Windir Environment Variable [prebuilt-rule-1-0-2-privilege-escalation-via-windir-environment-variable]

Identifies a privilege escalation attempt via a rogue Windows directory (Windir) environment variable. This is a known primitive that is often combined with other vulnerabilities to elevate privileges.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.html](https://www.tiraniddo.dev/2017/05/exploiting-environment-variables-in.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1933]

```js
registry where registry.path : ("HKEY_USERS\\*\\Environment\\windir", "HKEY_USERS\\*\\Environment\\systemroot") and
 not registry.data.strings : ("C:\\windows", "%SystemRoot%")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Path Interception by PATH Environment Variable
    * ID: T1574.007
    * Reference URL: [https://attack.mitre.org/techniques/T1574/007/](https://attack.mitre.org/techniques/T1574/007/)



