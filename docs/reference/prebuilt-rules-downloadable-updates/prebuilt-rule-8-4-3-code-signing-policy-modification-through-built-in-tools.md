---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-3-code-signing-policy-modification-through-built-in-tools.html
---

# Code Signing Policy Modification Through Built-in tools [prebuilt-rule-8-4-3-code-signing-policy-modification-through-built-in-tools]

Identifies attempts to disable/modify the code signing policy through system native utilities. Code signing provides authenticity on a program, and grants the user with the ability to check whether the program has been tampered with. By allowing the execution of unsigned or self-signed code, threat actors can craft and execute malicious code.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* macOS
* Threat Detection
* Defense Evasion
* Elastic Endgame

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4282]

```js
process where event.type == "start" and
(
  /* Windows */
  ((process.name: "bcdedit.exe" or process.pe.original_file_name == "bcdedit.exe") and   process.args: ("-set", "/set") and
  process.args: ("TESTSIGNING", "nointegritychecks", "loadoptions", "DISABLE_INTEGRITY_CHECKS")) or

  /* MacOS */
  (process.executable: "/usr/bin/csrutil" and process.args: "disable")
)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Subvert Trust Controls
    * ID: T1553
    * Reference URL: [https://attack.mitre.org/techniques/T1553/](https://attack.mitre.org/techniques/T1553/)

* Sub-technique:

    * Name: Code Signing Policy Modification
    * ID: T1553.006
    * Reference URL: [https://attack.mitre.org/techniques/T1553/006/](https://attack.mitre.org/techniques/T1553/006/)



