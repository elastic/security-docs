---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-remote-file-copy-via-teamviewer.html
---

# Remote File Copy via TeamViewer [prebuilt-rule-0-14-2-remote-file-copy-via-teamviewer]

Identifies an executable or script file remotely downloaded via a TeamViewer transfer session.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://web.archive.org/web/20230329160957/https://blog.menasec.net/2019/11/hunting-for-suspicious-use-of.html](https://web.archive.org/web/20230329160957/https://blog.menasec.net/2019/11/hunting-for-suspicious-use-of.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Command and Control

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1419]

```js
file where event.type == "creation" and process.name : "TeamViewer.exe" and
  file.extension : ("exe", "dll", "scr", "com", "bat", "ps1", "vbs", "vbe", "js", "wsh", "hta")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)

* Technique:

    * Name: Remote Access Software
    * ID: T1219
    * Reference URL: [https://attack.mitre.org/techniques/T1219/](https://attack.mitre.org/techniques/T1219/)



