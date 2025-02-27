---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-potential-protocol-tunneling-via-earthworm.html
---

# Potential Protocol Tunneling via EarthWorm [prebuilt-rule-1-0-2-potential-protocol-tunneling-via-earthworm]

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

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1465]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1696]

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



