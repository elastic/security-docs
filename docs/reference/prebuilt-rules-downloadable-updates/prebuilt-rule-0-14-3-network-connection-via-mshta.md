---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-network-connection-via-mshta.html
---

# Network Connection via Mshta [prebuilt-rule-0-14-3-network-connection-via-mshta]

Identifies mshta.exe making a network connection. This may indicate adversarial activity, as mshta.exe is often leveraged by adversaries to execute malicious scripts and evade detection.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.fireeye.com/blog/threat-research/2017/05/cyber-espionage-apt32.html](https://www.fireeye.com/blog/threat-research/2017/05/cyber-espionage-apt32.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1565]

```js
/* duplicate of Mshta Making Network Connections - c2d90150-0133-451c-a783-533e736c12d7 */

sequence by process.entity_id
  [process where process.name : "mshta.exe" and event.type == "start"]
  [network where process.name : "mshta.exe"]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Signed Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: Mshta
    * ID: T1218.005
    * Reference URL: [https://attack.mitre.org/techniques/T1218/005/](https://attack.mitre.org/techniques/T1218/005/)



