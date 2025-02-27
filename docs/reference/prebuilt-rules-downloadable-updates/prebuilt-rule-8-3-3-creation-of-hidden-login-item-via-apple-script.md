---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-creation-of-hidden-login-item-via-apple-script.html
---

# Creation of Hidden Login Item via Apple Script [prebuilt-rule-8-3-3-creation-of-hidden-login-item-via-apple-script]

Identifies the execution of osascript to create a hidden login item. This may indicate an attempt to persist a malicious program while concealing its presence.

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
* macOS
* Threat Detection
* Persistence
* Execution

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2971]



## Rule query [_rule_query_3443]

```js
process where event.type in ("start", "process_started") and process.name : "osascript" and
 process.command_line : "osascript*login item*hidden:true*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Autostart Execution
    * ID: T1547
    * Reference URL: [https://attack.mitre.org/techniques/T1547/](https://attack.mitre.org/techniques/T1547/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: AppleScript
    * ID: T1059.002
    * Reference URL: [https://attack.mitre.org/techniques/T1059/002/](https://attack.mitre.org/techniques/T1059/002/)

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Plist File Modification
    * ID: T1647
    * Reference URL: [https://attack.mitre.org/techniques/T1647/](https://attack.mitre.org/techniques/T1647/)



