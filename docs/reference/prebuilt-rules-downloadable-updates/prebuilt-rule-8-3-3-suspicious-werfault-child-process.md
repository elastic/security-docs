---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-suspicious-werfault-child-process.html
---

# Suspicious WerFault Child Process [prebuilt-rule-8-3-3-suspicious-werfault-child-process]

A suspicious WerFault child process was detected, which may indicate an attempt to run unnoticed. Verify process details such as command line, network connections, file writes and parent process details as well.

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

**References**:

* [https://www.hexacorn.com/blog/2019/09/19/silentprocessexit-quick-look-under-the-hood/](https://www.hexacorn.com/blog/2019/09/19/silentprocessexit-quick-look-under-the-hood/)
* [https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/persistence_SilentProcessExit_ImageHijack_sysmon_13_1.evtx](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Persistence/persistence_SilentProcessExit_ImageHijack_sysmon_13_1.evtx)
* [https://web.archive.org/web/20230530011556/https://blog.menasec.net/2021/01/](https://web.archive.org/web/20230530011556/https://blog.menasec.net/2021/01/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3070]



## Rule query [_rule_query_3571]

```js
process where event.type == "start" and
  process.parent.name : "WerFault.exe" and
  not process.name : ("cofire.exe",
                      "psr.exe",
                      "VsJITDebugger.exe",
                      "TTTracer.exe",
                      "rundll32.exe",
                      "LogiOptionsMgr.exe") and
  not process.args : ("/LOADSAVEDWINDOWS",
                      "/restore",
                      "RestartByRestartManager*",
                      "--restarted",
                      "createdump",
                      "dontsend",
                      "/watson")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)



