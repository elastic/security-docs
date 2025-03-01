---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-incoming-dcom-lateral-movement-with-mmc.html
---

# Incoming DCOM Lateral Movement with MMC [prebuilt-rule-0-14-2-incoming-dcom-lateral-movement-with-mmc]

Identifies the use of Distributed Component Object Model (DCOM) to run commands from a remote host, which are launched via the MMC20 Application COM Object. This behavior may indicate an attacker abusing a DCOM application to move laterally.

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

* [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Lateral Movement

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1464]

```js
sequence by host.id with maxspan=1m
 [network where event.type == "start" and process.name : "mmc.exe" and
  source.port >= 49152 and destination.port >= 49152 and source.address not in ("127.0.0.1", "::1") and
  network.direction == "incoming" and network.transport == "tcp"
 ] by process.entity_id
 [process where event.type in ("start", "process_started") and process.parent.name : "mmc.exe"
 ] by process.parent.entity_id
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: Distributed Component Object Model
    * ID: T1021.003
    * Reference URL: [https://attack.mitre.org/techniques/T1021/003/](https://attack.mitre.org/techniques/T1021/003/)



