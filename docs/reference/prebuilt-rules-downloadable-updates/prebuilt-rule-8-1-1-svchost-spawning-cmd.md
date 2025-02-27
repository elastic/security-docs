---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-svchost-spawning-cmd.html
---

# Svchost spawning Cmd [prebuilt-rule-8-1-1-svchost-spawning-cmd]

Identifies a suspicious parent child process relationship with cmd.exe descending from svchost.exe

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Execution

**Version**: 12

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1779]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_2053]

```js
process where event.type == "start" and
  process.parent.name : "svchost.exe" and process.name : "cmd.exe" and
  not (process.pe.original_file_name : "cmd.exe" and process.args : (
    "??:\\Program Files\\Npcap\\CheckStatus.bat?",
    "?:\\Program Files\\Npcap\\CheckStatus.bat",
    "\\system32\\cleanmgr.exe",
    "?:\\Windows\\system32\\silcollector.cmd",
    "\\system32\\AppHostRegistrationVerifier.exe",
    "\\system32\\ServerManagerLauncher.exe"))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)



