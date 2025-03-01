---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/discovery-of-internet-capabilities-via-built-in-tools.html
---

# Discovery of Internet Capabilities via Built-in Tools [discovery-of-internet-capabilities-via-built-in-tools]

Identifies the use of built-in tools attackers can use to check for Internet connectivity on compromised systems. These results may be used to determine communication capabilities with C2 servers, or to identify routes, redirectors, and proxy servers.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Discovery
* Rule Type: BBR
* Data Source: Elastic Defend

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_284]

```js
host.os.type:windows and event.category:process and event.type:start and
process.name.caseless:("ping.exe" or "tracert.exe" or "pathping.exe") and
not process.args:("127.0.0.1" or "0.0.0.0" or "localhost" or "::1")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Network Configuration Discovery
    * ID: T1016
    * Reference URL: [https://attack.mitre.org/techniques/T1016/](https://attack.mitre.org/techniques/T1016/)

* Sub-technique:

    * Name: Internet Connection Discovery
    * ID: T1016.001
    * Reference URL: [https://attack.mitre.org/techniques/T1016/001/](https://attack.mitre.org/techniques/T1016/001/)



