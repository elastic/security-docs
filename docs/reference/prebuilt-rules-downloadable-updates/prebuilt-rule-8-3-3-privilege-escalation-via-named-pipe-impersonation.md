---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-privilege-escalation-via-named-pipe-impersonation.html
---

# Privilege Escalation via Named Pipe Impersonation [prebuilt-rule-8-3-3-privilege-escalation-via-named-pipe-impersonation]

Identifies a privilege escalation attempt via named pipe impersonation. An adversary may abuse this technique by utilizing a framework such Metasploit’s meterpreter getsystem command.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation](https://www.ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3202]



## Rule query [_rule_query_3748]

```js
process where event.type == "start" and
 process.pe.original_file_name in ("Cmd.Exe", "PowerShell.EXE") and
 process.args : "echo" and process.args : ">" and process.args : "\\\\.\\pipe\\*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Access Token Manipulation
    * ID: T1134
    * Reference URL: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)



