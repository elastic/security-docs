---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/possible-fin7-dga-command-and-control-behavior.html
---

# Possible FIN7 DGA Command and Control Behavior [possible-fin7-dga-command-and-control-behavior]

This rule detects a known command and control pattern in network events. The FIN7 threat group is known to use this command and control technique, while maintaining persistence in their target’s network.

**Rule type**: query

**Rule indices**:

* packetbeat-*
* auditbeat-*
* filebeat-*
* logs-network_traffic.*
* logs-panw.panos*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html](https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.md)

**Tags**:

* Use Case: Threat Detection
* Tactic: Command and Control
* Domain: Endpoint
* Data Source: PAN-OS
* Resources: Investigation Guide

**Version**: 107

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_641]

**Triage and analysis**

In the event this rule identifies benign domains in your environment, the `destination.domain` field in the rule can be modified to include those domains. Example: `...AND NOT destination.domain:(zoom.us OR benign.domain1 OR benign.domain2)`.


## Rule query [_rule_query_683]

```js
(event.dataset: (network_traffic.tls OR network_traffic.http) OR
    (event.category: (network OR network_traffic) AND type: (tls OR http) AND network.transport: tcp)) AND
destination.domain:/[a-zA-Z]{4,5}\.(pw|us|club|info|site|top)/ AND NOT destination.domain:zoom.us
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



