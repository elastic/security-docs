---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-linux-process-hooking-via-gdb.html
---

# Linux Process Hooking via GDB [prebuilt-rule-8-17-3-linux-process-hooking-via-gdb]

This rule monitors for potential memory dumping through gdb. Attackers may leverage memory dumping techniques to attempt secret extraction from privileged processes. Tools that display this behavior include "truffleproc" and "bash-memory-dump". This behavior should not happen by default, and should be investigated thoroughly.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*
* auditbeat-*
* logs-auditd_manager.auditd-*
* logs-crowdstrike.fdr*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/controlplaneio/truffleproc](https://github.com/controlplaneio/truffleproc)
* [https://github.com/hajzer/bash-memory-dump](https://github.com/hajzer/bash-memory-dump)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Credential Access
* Data Source: Elastic Defend
* Data Source: Elastic Endgame
* Data Source: Auditd Manager
* Data Source: Crowdstrike
* Data Source: SentinelOne

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4860]

```js
process where host.os.type == "linux" and event.type == "start" and event.action in ("exec", "exec_event", "start", "ProcessRollup2", "executed", "process_started")
 and process.name == "gdb" and process.args in ("--pid", "-p") and
/* Covered by d4ff2f53-c802-4d2e-9fb9-9ecc08356c3f */
process.args != "1"
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

    * Name: Proc Filesystem
    * ID: T1003.007
    * Reference URL: [https://attack.mitre.org/techniques/T1003/007/](https://attack.mitre.org/techniques/T1003/007/)



