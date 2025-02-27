---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-ipsec-nat-traversal-port-activity.html
---

# IPSEC NAT Traversal Port Activity [prebuilt-rule-8-4-2-ipsec-nat-traversal-port-activity]

This rule detects events that could be describing IPSEC NAT Traversal traffic. IPSEC is a VPN technology that allows one system to talk to another using encrypted tunnels. NAT Traversal enables these tunnels to communicate over the Internet where one of the sides is behind a NAT router gateway. This may be common on your network, but this technique is also used by threat actors to avoid detection.

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

**References**: None

**Tags**:

* Elastic
* Host
* Network
* Threat Detection
* Command and Control
* Host

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3965]

```js
event.category:(network or network_traffic) and network.transport:udp and destination.port:4500
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)



