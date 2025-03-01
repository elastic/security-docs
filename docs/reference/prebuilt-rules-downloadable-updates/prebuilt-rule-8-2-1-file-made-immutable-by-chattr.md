---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-file-made-immutable-by-chattr.html
---

# File made Immutable by Chattr [prebuilt-rule-8-2-1-file-made-immutable-by-chattr]

Detects a file being made immutable using the chattr binary. Making a file immutable means it cannot be deleted or renamed, no link can be created to this file, most of the file’s metadata can not be modified, and the file can not be opened in write mode. Threat actors will commonly utilize this to prevent tampering or modification of their malicious files or any system files they have modified for purposes of persistence (e.g .ssh, /etc/passwd, etc.).

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 33

**References**: None

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Defense Evasion

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2028]



## Rule query [_rule_query_2313]

```js
process where event.type == "start" and user.name == "root" and process.executable : "/usr/bin/chattr" and process.args : ("-*i*", "+*i*") and not process.parent.executable: "/lib/systemd/systemd"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: File and Directory Permissions Modification
    * ID: T1222
    * Reference URL: [https://attack.mitre.org/techniques/T1222/](https://attack.mitre.org/techniques/T1222/)

* Sub-technique:

    * Name: Linux and Mac File and Directory Permissions Modification
    * ID: T1222.002
    * Reference URL: [https://attack.mitre.org/techniques/T1222/002/](https://attack.mitre.org/techniques/T1222/002/)



