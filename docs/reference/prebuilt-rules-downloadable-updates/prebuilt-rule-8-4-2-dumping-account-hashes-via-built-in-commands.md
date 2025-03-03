---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-dumping-account-hashes-via-built-in-commands.html
---

# Dumping Account Hashes via Built-In Commands [prebuilt-rule-8-4-2-dumping-account-hashes-via-built-in-commands]

Identifies the execution of macOS built-in commands used to dump user account hashes. Adversaries may attempt to dump credentials to obtain account login information in the form of a hash. These hashes can be cracked or leveraged for lateral movement.

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

* [https://apple.stackexchange.com/questions/186893/os-x-10-9-where-are-password-hashes-stored](https://apple.stackexchange.com/questions/186893/os-x-10-9-where-are-password-hashes-stored)
* [https://www.unix.com/man-page/osx/8/mkpassdb/](https://www.unix.com/man-page/osx/8/mkpassdb/)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Credential Access

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3900]

```js
event.category:process and event.type:start and
 process.name:(defaults or mkpassdb) and process.args:(ShadowHashData or "-dump")
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



