---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-3-smtp-on-port-26-tcp.html
---

# SMTP on Port 26/TCP [prebuilt-rule-0-13-3-smtp-on-port-26-tcp]

This rule detects events that may indicate use of SMTP on TCP port 26. This port is commonly used by several popular mail transfer agents to deconflict with the default SMTP port 25. This port has also been used by a malware family called BadPatch for command and control of Windows systems.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* filebeat-*
* packetbeat-*
* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://unit42.paloaltonetworks.com/unit42-badpatch/](https://unit42.paloaltonetworks.com/unit42-badpatch/)
* [https://isc.sans.edu/forums/diary/Next+up+whats+up+with+TCP+port+26/25564/](https://isc.sans.edu/forums/diary/Next+up+whats+up+with+TCP+port+26/25564/)

**Tags**:

* Elastic
* Host
* Network
* Threat Detection
* Command and Control
* Host

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1311]

```js
event.category:(network or network_traffic) and network.transport:tcp and (destination.port:26 or (event.dataset:zeek.smtp and destination.port:26))
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Tactic:

    * Name: Exfiltration
    * ID: TA0010
    * Reference URL: [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)

* Technique:

    * Name: Exfiltration Over Alternative Protocol
    * ID: T1048
    * Reference URL: [https://attack.mitre.org/techniques/T1048/](https://attack.mitre.org/techniques/T1048/)



