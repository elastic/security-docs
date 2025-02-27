---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-installutil-process-making-network-connections.html
---

# InstallUtil Process Making Network Connections [prebuilt-rule-8-4-2-installutil-process-making-network-connections]

Identifies InstallUtil.exe making outbound network connections. This may indicate adversarial activity as InstallUtil is often leveraged by adversaries to execute code and evade detection.

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
* Defense Evasion

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4059]

```js
/* the benefit of doing this as an eql sequence vs kql is this will limit to alerting only on the first network connection */

sequence by process.entity_id
  [process where event.type == "start" and process.name : "installutil.exe"]
  [network where process.name : "installutil.exe" and network.direction : ("outgoing", "egress")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: System Binary Proxy Execution
    * ID: T1218
    * Reference URL: [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

* Sub-technique:

    * Name: InstallUtil
    * ID: T1218.004
    * Reference URL: [https://attack.mitre.org/techniques/T1218/004/](https://attack.mitre.org/techniques/T1218/004/)



