---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-control-panel-process-with-unusual-arguments.html
---

# Control Panel Process with Unusual Arguments [prebuilt-rule-0-14-2-control-panel-process-with-unusual-arguments]

Identifies unusual instances of Control Panel with suspicious keywords or paths in the process command line value. Adversaries may abuse Control.exe to proxy execution of malicious code.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.joesandbox.com/analysis/476188/1/html](https://www.joesandbox.com/analysis/476188/1/html)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1401]

```js
process where event.type in ("start", "process_started") and
 process.executable : ("?:\\Windows\\SysWOW64\\control.exe", "?:\\Windows\\System32\\control.exe") and
 process.command_line :
          ("*.jpg*",
           "*.png*",
           "*.gif*",
           "*.bmp*",
           "*.jpeg*",
           "*.TIFF*",
           "*.inf*",
           "*.dat*",
           "*.cpl:*/*",
           "*../../..*",
           "*/AppData/Local/*",
           "*:\\Users\\Public\\*",
           "*\\AppData\\Local\\*")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Signed Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Control Panel
    * ID: T1218.002
    * Reference URL: [https://attack.mitre.org/techniques/T1218/002/](https://attack.mitre.org/techniques/T1218/002/)



