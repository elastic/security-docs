---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-halfbaked-command-and-control-beacon.html
---

# Halfbaked Command and Control Beacon [prebuilt-rule-8-4-2-halfbaked-command-and-control-beacon]

Halfbaked is a malware family used to establish persistence in a contested network. This rule detects a network activity algorithm leveraged by Halfbaked implant beacons for command and control.

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

* [https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html](https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.md)
* [https://attack.mitre.org/software/S0151/](https://attack.mitre.org/software/S0151/)

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

## Investigation guide [_investigation_guide_3330]

## Threat intel

This activity has been observed in FIN7 campaigns.

## Rule query [_rule_query_3964]

```js
event.category:(network OR network_traffic) AND network.protocol:http AND
  network.transport:tcp AND url.full:/http:\/\/[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}\/cd/ AND
  destination.port:(53 OR 80 OR 8080 OR 443)
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



