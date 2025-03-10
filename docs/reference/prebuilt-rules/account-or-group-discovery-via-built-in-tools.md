---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/account-or-group-discovery-via-built-in-tools.html
---

# Account or Group Discovery via Built-In Tools [account-or-group-discovery-via-built-in-tools]

Adversaries may use built-in applications to get a listing of local system or domain accounts and groups.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Linux
* OS: macOS
* Use Case: Threat Detection
* Tactic: Discovery
* Rule Type: BBR
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_124]

```js
process where event.type == "start" and event.action in ("exec", "exec_event", "executed", "process_started") and (
  (process.name in ("groups", "id")) or
  (process.name == "dscl" and process.args : ("/Active Directory/*", "/Users*", "/Groups*")) or
  (process.name == "dscacheutil" and process.args in ("user", "group")) or
  (process.args in ("/etc/passwd", "/etc/master.passwd", "/etc/sudoers")) or
  (process.name == "getent" and process.args in ("passwd", "group"))
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Permission Groups Discovery
    * ID: T1069
    * Reference URL: [https://attack.mitre.org/techniques/T1069/](https://attack.mitre.org/techniques/T1069/)

* Sub-technique:

    * Name: Local Groups
    * ID: T1069.001
    * Reference URL: [https://attack.mitre.org/techniques/T1069/001/](https://attack.mitre.org/techniques/T1069/001/)

* Sub-technique:

    * Name: Domain Groups
    * ID: T1069.002
    * Reference URL: [https://attack.mitre.org/techniques/T1069/002/](https://attack.mitre.org/techniques/T1069/002/)

* Technique:

    * Name: Account Discovery
    * ID: T1087
    * Reference URL: [https://attack.mitre.org/techniques/T1087/](https://attack.mitre.org/techniques/T1087/)

* Sub-technique:

    * Name: Local Account
    * ID: T1087.001
    * Reference URL: [https://attack.mitre.org/techniques/T1087/001/](https://attack.mitre.org/techniques/T1087/001/)

* Sub-technique:

    * Name: Domain Account
    * ID: T1087.002
    * Reference URL: [https://attack.mitre.org/techniques/T1087/002/](https://attack.mitre.org/techniques/T1087/002/)



