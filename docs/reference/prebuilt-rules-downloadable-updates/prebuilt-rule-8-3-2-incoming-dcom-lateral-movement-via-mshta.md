---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-incoming-dcom-lateral-movement-via-mshta.html
---

# Incoming DCOM Lateral Movement via MSHTA [prebuilt-rule-8-3-2-incoming-dcom-lateral-movement-via-mshta]

Identifies the use of Distributed Component Object Model (DCOM) to execute commands from a remote host, which are launched via the HTA Application COM Object. This behavior may indicate an attacker abusing a DCOM application to move laterally while attempting to evade detection.

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

* [https://codewhitesec.blogspot.com/2018/07/lethalhta.html](https://codewhitesec.blogspot.com/2018/07/lethalhta.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Lateral Movement

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2896]

```js
sequence with maxspan=1m
  [process where event.type == "start" and
     process.name : "mshta.exe" and process.args : "-Embedding"
  ] by host.id, process.entity_id
  [network where event.type == "start" and process.name : "mshta.exe" and
     network.direction : ("incoming", "ingress") and network.transport == "tcp" and
     source.port > 49151 and destination.port > 49151 and source.ip != "127.0.0.1" and source.ip != "::1"
  ] by host.id, process.entity_id
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

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Mshta
    * ID: T1218.005
    * Reference URL: [https://attack.mitre.org/techniques/T1218/005/](https://attack.mitre.org/techniques/T1218/005/)



