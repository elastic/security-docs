---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-file-permission-modification-in-writable-directory.html
---

# File Permission Modification in Writable Directory [prebuilt-rule-8-3-3-file-permission-modification-in-writable-directory]

Identifies file permission modifications in common writable directories by a non-root user. Adversaries often drop files or payloads into a writable directory and change permissions prior to execution.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Defense Evasion

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3377]

```js
event.category:process and event.type:(start or process_started) and
  process.name:(chmod or chown or chattr or chgrp) and
  process.working_directory:(/tmp or /var/tmp or /dev/shm) and
  not user.name:root
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



