---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-potential-protocol-tunneling-via-earthworm.html
---

# Potential Protocol Tunneling via EarthWorm [prebuilt-rule-8-4-2-potential-protocol-tunneling-via-earthworm]

Identifies the execution of the EarthWorm tunneler. Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection and network filtering, or to enable access to otherwise unreachable systems.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [http://rootkiter.com/EarthWorm/](http://rootkiter.com/EarthWorm/)
* [https://decoded.avast.io/luigicamastra/apt-group-targeting-governmental-agencies-in-east-asia/](https://decoded.avast.io/luigicamastra/apt-group-targeting-governmental-agencies-in-east-asia/)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Command and Control

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3290]



## Rule query [_rule_query_3855]

```js
process where event.type == "start" and
 process.args : "-s" and process.args : "-d" and process.args : "rssocks"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Protocol Tunneling
    * ID: T1572
    * Reference URL: [https://attack.mitre.org/techniques/T1572/](https://attack.mitre.org/techniques/T1572/)



