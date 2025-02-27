---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-potential-dns-tunneling-via-iodine.html
---

# Potential DNS Tunneling via Iodine [prebuilt-rule-8-7-1-potential-dns-tunneling-via-iodine]

Iodine is a tool for tunneling Internet protocol version 4 (IPV4) traffic over the DNS protocol to circumvent firewalls, network security groups, and network access lists while evading detection.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Command and Control
* Elastic Endgame

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4681]

```js
event.category:process and event.type:(start or process_started) and process.name:(iodine or iodined)
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



