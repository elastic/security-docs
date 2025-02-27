---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-incoming-execution-via-powershell-remoting.html
---

# Incoming Execution via PowerShell Remoting [prebuilt-rule-0-14-3-incoming-execution-via-powershell-remoting]

Identifies remote execution via Windows PowerShell remoting. Windows PowerShell remoting allows for running any Windows PowerShell command on one or more remote computers. This could be an indication of lateral movement.

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

* [https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.1](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.1)

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

## Rule query [_rule_query_1555]

```js
sequence by host.id with maxspan = 30s
   [network where network.direction : ("incoming", "ingress") and destination.port in (5985, 5986) and
    network.protocol == "http" and source.address != "127.0.0.1" and source.address != "::1"
   ]
   [process where event.type == "start" and process.parent.name : "wsmprovhost.exe" and not process.name : "conhost.exe"]
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



