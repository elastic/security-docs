---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/potential-process-injection-from-malicious-document.html
---

# Potential Process Injection from Malicious Document [potential-process-injection-from-malicious-document]

Identifies child processes of frequently targeted Microsoft Office applications (Word, PowerPoint, Excel) with unusual process arguments and path. This behavior is often observed during exploitation of Office applications or from documents with malicious macros.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Defense Evasion
* Tactic: Privilege Escalation
* Tactic: Initial Access
* Rule Type: BBR
* Data Source: Elastic Defend

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_793]

```js
process where host.os.type == "windows" and event.action == "start" and
  process.parent.name : ("excel.exe", "powerpnt.exe", "winword.exe") and
  process.args_count == 1 and
  process.executable : (
    "?:\\Windows\\SysWOW64\\*.exe", "?:\\Windows\\system32\\*.exe"
  ) and
  not (process.executable : "?:\\Windows\\System32\\spool\\drivers\\x64\\*" and
       process.code_signature.trusted == true and not process.code_signature.subject_name : "Microsoft *") and
  not process.executable : (
    "?:\\Windows\\Sys*\\Taskmgr.exe",
    "?:\\Windows\\Sys*\\ctfmon.exe",
    "?:\\Windows\\System32\\notepad.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Process Injection
    * ID: T1055
    * Reference URL: [https://attack.mitre.org/techniques/T1055/](https://attack.mitre.org/techniques/T1055/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Attachment
    * ID: T1566.001
    * Reference URL: [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)



