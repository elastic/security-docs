---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/memory-dump-file-with-unusual-extension.html
---

# Memory Dump File with Unusual Extension [memory-dump-file-with-unusual-extension]

Identifies the creation of a memory dump file with an unusual extension, which can indicate an attempt to disguise a memory dump as another file type to bypass security defenses.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file-*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Credential Access
* Tactic: Defense Evasion
* Data Source: Elastic Defend
* Rule Type: BBR

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_538]

```js
file where host.os.type == "windows" and event.type == "creation" and

  /* MDMP header */
  file.Ext.header_bytes : "4d444d50*" and
  not file.extension : ("dmp", "mdmp", "hdmp", "edmp", "full", "tdref", "cg", "tmp", "dat") and
  not
  (
    process.executable : "?:\\Program Files\\Endgame\\esensor.exe" and
    process.code_signature.trusted == true and length(file.extension) == 0
  ) and
  not
  (
    process.name : "System" and file.extension : "tmpscan"
  )
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

* Sub-technique:

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)

* Sub-technique:

    * Name: Masquerade File Type
    * ID: T1036.008
    * Reference URL: [https://attack.mitre.org/techniques/T1036/008/](https://attack.mitre.org/techniques/T1036/008/)



