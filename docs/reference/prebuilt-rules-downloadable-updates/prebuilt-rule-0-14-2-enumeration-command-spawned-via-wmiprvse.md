---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-enumeration-command-spawned-via-wmiprvse.html
---

# Enumeration Command Spawned via WMIPrvSE [prebuilt-rule-0-14-2-enumeration-command-spawned-via-wmiprvse]

Identifies native Windows host and network enumeration commands spawned by the Windows Management Instrumentation Provider Service (WMIPrvSE).

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

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1453]

```js
process where event.type in ("start", "process_started") and
  process.name:
  (
    "arp.exe",
    "dsquery.exe",
    "dsget.exe",
    "gpresult.exe",
    "hostname.exe",
    "ipconfig.exe",
    "nbtstat.exe",
    "net.exe",
    "net1.exe",
    "netsh.exe",
    "netstat.exe",
    "nltest.exe",
    "ping.exe",
    "qprocess.exe",
    "quser.exe",
    "qwinsta.exe",
    "reg.exe",
    "sc.exe",
    "systeminfo.exe",
    "tasklist.exe",
    "tracert.exe",
    "whoami.exe"
  ) and
  process.parent.name:"wmiprvse.exe"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Windows Management Instrumentation
    * ID: T1047
    * Reference URL: [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: Software Discovery
    * ID: T1518
    * Reference URL: [https://attack.mitre.org/techniques/T1518/](https://attack.mitre.org/techniques/T1518/)

* Technique:

    * Name: Account Discovery
    * ID: T1087
    * Reference URL: [https://attack.mitre.org/techniques/T1087/](https://attack.mitre.org/techniques/T1087/)

* Technique:

    * Name: Remote System Discovery
    * ID: T1018
    * Reference URL: [https://attack.mitre.org/techniques/T1018/](https://attack.mitre.org/techniques/T1018/)



