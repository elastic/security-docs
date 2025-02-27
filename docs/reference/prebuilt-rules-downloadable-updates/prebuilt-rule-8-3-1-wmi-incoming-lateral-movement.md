---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-wmi-incoming-lateral-movement.html
---

# WMI Incoming Lateral Movement [prebuilt-rule-8-3-1-wmi-incoming-lateral-movement]

Identifies processes executed via Windows Management Instrumentation (WMI) on a remote host. This could be indicative of adversary lateral movement, but could be noisy if administrators use WMI to remotely manage hosts.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

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
* Threat Detection
* Lateral Movement

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2682]

```js
sequence by host.id with maxspan = 2s

 /* Accepted Incoming RPC connection by Winmgmt service */

  [network where process.name : "svchost.exe" and network.direction : ("incoming", "ingress") and
   source.ip != "127.0.0.1" and source.ip != "::1" and source.port >= 49152 and destination.port >= 49152
  ]

  /* Excluding Common FPs Nessus and SCCM */

  [process where event.type in ("start", "process_started") and process.parent.name : "WmiPrvSE.exe" and
   not process.args : ("C:\\windows\\temp\\nessus_*.txt",
                       "C:\\windows\\TEMP\\nessus_*.TMP",
                       "C:\\Windows\\CCM\\SystemTemp\\*",
                       "C:\\Windows\\CCMCache\\*",
                       "C:\\CCM\\Cache\\*")
   ]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Windows Management Instrumentation
    * ID: T1047
    * Reference URL: [https://attack.mitre.org/techniques/T1047/](https://attack.mitre.org/techniques/T1047/)



