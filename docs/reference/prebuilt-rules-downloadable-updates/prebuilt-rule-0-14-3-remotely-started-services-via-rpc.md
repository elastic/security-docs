---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-remotely-started-services-via-rpc.html
---

# Remotely Started Services via RPC [prebuilt-rule-0-14-3-remotely-started-services-via-rpc]

Identifies remote execution of Windows services over remote procedure call (RPC). This could be indicative of lateral movement, but will be noisy if commonly done by administrators."

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

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1557]

```js
sequence with maxspan=1s
   [network where process.name : "services.exe" and
      network.direction : ("incoming", "ingress") and network.transport == "tcp" and
      source.port >= 49152 and destination.port >= 49152 and source.address not in ("127.0.0.1", "::1")
   ] by host.id, process.entity_id

   [process where event.type in ("start", "process_started") and process.parent.name : "services.exe" and
       not (process.name : "svchost.exe" and process.args : "tiledatamodelsvc") and
       not (process.name : "msiexec.exe" and process.args : "/V")

    /* uncomment if psexec is noisy in your environment */
    /* and not process.name : "PSEXESVC.exe" */
   ] by host.id, process.parent.entity_id
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



