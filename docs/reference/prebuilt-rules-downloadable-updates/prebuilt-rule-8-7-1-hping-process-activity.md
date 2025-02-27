---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-hping-process-activity.html
---

# Hping Process Activity [prebuilt-rule-8-7-1-hping-process-activity]

Hping ran on a Linux host. Hping is a FOSS command-line packet analyzer and has the ability to construct network packets for a wide variety of network security testing applications, including scanning and firewall auditing.

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

* [https://en.wikipedia.org/wiki/Hping](https://en.wikipedia.org/wiki/Hping)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Discovery
* Elastic Endgame

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4697]

```js
event.category:process and event.type:(start or process_started) and process.name:(hping or hping2 or hping3)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Information Discovery
    * ID: T1082
    * Reference URL: [https://attack.mitre.org/techniques/T1082/](https://attack.mitre.org/techniques/T1082/)



