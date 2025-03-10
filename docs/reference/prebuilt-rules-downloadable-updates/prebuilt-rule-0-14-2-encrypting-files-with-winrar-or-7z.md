---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-encrypting-files-with-winrar-or-7z.html
---

# Encrypting Files with WinRar or 7z [prebuilt-rule-0-14-2-encrypting-files-with-winrar-or-7z]

Identifies use of WinRar or 7z to create an encrypted files. Adversaries will often compress and encrypt data in preparation for exfiltration.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.welivesecurity.com/2020/12/02/turla-crutch-keeping-back-door-open/](https://www.welivesecurity.com/2020/12/02/turla-crutch-keeping-back-door-open/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Collection

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1413]

```js
process where event.type in ("start", "process_started") and
  ((process.name:"rar.exe" or process.code_signature.subject_name == "win.rar GmbH" or
      process.pe.original_file_name == "Command line RAR") and
    process.args == "a" and process.args : ("-hp*", "-p*", "-dw", "-tb", "-ta", "/hp*", "/p*", "/dw", "/tb", "/ta"))

  or
  (process.pe.original_file_name in ("7z.exe", "7za.exe") and
     process.args == "a" and process.args : ("-p*", "-sdel"))

  /* uncomment if noisy for backup software related FPs */
  /* not process.parent.executable : ("C:\\Program Files\\*.exe", "C:\\Program Files (x86)\\*.exe") */
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Archive Collected Data
    * ID: T1560
    * Reference URL: [https://attack.mitre.org/techniques/T1560/](https://attack.mitre.org/techniques/T1560/)

* Sub-technique:

    * Name: Archive via Utility
    * ID: T1560.001
    * Reference URL: [https://attack.mitre.org/techniques/T1560/001/](https://attack.mitre.org/techniques/T1560/001/)



