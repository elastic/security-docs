---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-cobalt-strike-command-and-control-beacon.html
---

# Cobalt Strike Command and Control Beacon [prebuilt-rule-8-4-1-cobalt-strike-command-and-control-beacon]

Cobalt Strike is a threat emulation platform commonly modified and used by adversaries to conduct network attack and exploitation campaigns. This rule detects a network activity algorithm leveraged by Cobalt Strike implant beacons for command and control.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* filebeat-*
* packetbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.morphisec.com/fin7-attacks-restaurant-industry](https://blog.morphisec.com/fin7-attacks-restaurant-industry)
* [https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.md)
* [https://www.elastic.co/security-labs/collecting-cobalt-strike-beacons-with-the-elastic-stack](https://www.elastic.co/security-labs/collecting-cobalt-strike-beacons-with-the-elastic-stack)

**Tags**:

* Elastic
* Network
* Threat Detection
* Command and Control
* Host

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2663]

## Threat intel

This activity has been observed in FIN7 campaigns.

## Rule query [_rule_query_3052]

```js
event.category:(network OR network_traffic) AND type:(tls OR http) AND network.transport:tcp AND destination.domain:/[a-z]{3}.stage.[0-9]{8}\..*/
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)

* Technique:

    * Name: Dynamic Resolution
    * ID: T1568
    * Reference URL: [https://attack.mitre.org/techniques/T1568/](https://attack.mitre.org/techniques/T1568/)

* Sub-technique:

    * Name: Domain Generation Algorithms
    * ID: T1568.002
    * Reference URL: [https://attack.mitre.org/techniques/T1568/002/](https://attack.mitre.org/techniques/T1568/002/)



