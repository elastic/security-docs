---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-potential-dns-tunneling-via-nslookup.html
---

# Potential DNS Tunneling via NsLookup [prebuilt-rule-0-14-2-potential-dns-tunneling-via-nslookup]

This rule identifies a large number (15) of nslookup.exe executions with an explicit query type from the same host. This may indicate command and control activity utilizing the DNS protocol.

**Rule type**: threshold

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild-overview-of-oilrigs-dns-tunneling/](https://unit42.paloaltonetworks.com/dns-tunneling-in-the-wild-overview-of-oilrigs-dns-tunneling/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Command and Control

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1415]

```js
event.category:process and event.type:start and process.name:nslookup.exe and process.args:(-querytype=* or -qt=* or -q=* or -type=*)
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

* Sub-technique:

    * Name: DNS
    * ID: T1071.004
    * Reference URL: [https://attack.mitre.org/techniques/T1071/004/](https://attack.mitre.org/techniques/T1071/004/)



