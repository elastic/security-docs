---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-telnet-port-activity.html
---

# Telnet Port Activity [prebuilt-rule-8-1-1-telnet-port-activity]

This rule detects network events that may indicate the use of Telnet traffic. Telnet is commonly used by system administrators to remotely control older or embedded systems using the command line shell. It should almost never be directly exposed to the Internet, as it is frequently targeted and exploited by threat actors as an initial access or backdoor vector. As a plain-text protocol, it may also expose usernames and passwords to anyone capable of observing the traffic.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* filebeat-*
* packetbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Network
* Threat Detection
* Command and Control
* Host

**Version**: 12

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1979]

```js
event.category:(network or network_traffic) and network.transport:tcp and destination.port:23
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Exploit Public-Facing Application
    * ID: T1190
    * Reference URL: [https://attack.mitre.org/techniques/T1190/](https://attack.mitre.org/techniques/T1190/)



