---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-shadow-file-read-via-command-line-utilities.html
---

# Shadow File Read via Command Line Utilities [prebuilt-rule-8-3-2-shadow-file-read-via-command-line-utilities]

Identifies the manual reading of the /etc/shadow file via the commandline using standard system utilities. Threat actors will attempt to read this file, after elevating their privileges to root, in order to gain valid credentials they can utilize to move laterally undetected and access additional resources.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Privilege Escalation

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2710]

```js
process where event.type == "start" and event.action == "exec" and user.name == "root" and
process.args : "/etc/shadow" and
not process.executable: ("/usr/bin/find", "/usr/bin/cmp", "/bin/ls", "/usr/sbin/restorecon", "/usr/bin/uniq") and
not process.parent.executable: "/bin/dracut"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)



