---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-2-execution-via-tsclient-mountpoint.html
---

# Execution via TSClient Mountpoint [prebuilt-rule-8-3-2-execution-via-tsclient-mountpoint]

Identifies execution from the Remote Desktop Protocol (RDP) shared mountpoint tsclient on the target host. This may indicate a lateral movement attempt.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://posts.specterops.io/revisiting-remote-desktop-lateral-movement-8fb905cb46c3](https://posts.specterops.io/revisiting-remote-desktop-lateral-movement-8fb905cb46c3)

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

## Investigation guide [_investigation_guide_2524]



## Rule query [_rule_query_2902]

```js
process where event.type == "start" and process.executable : "\\Device\\Mup\\tsclient\\*.exe"
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



