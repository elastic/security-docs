---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-apple-script-execution-followed-by-network-connection.html
---

# Apple Script Execution followed by Network Connection [prebuilt-rule-8-4-2-apple-script-execution-followed-by-network-connection]

Detects execution via the Apple script interpreter (osascript) followed by a network connection from the same process within a short time period. Adversaries may use malicious scripts for execution and command and control.

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

* [https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/index.html](https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/index.md)
* [https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Command and Control
* Execution

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3924]

```js
sequence by host.id, process.entity_id with maxspan=30s
 [process where event.type == "start" and process.name == "osascript"]
 [network where event.type != "end" and process.name == "osascript" and destination.ip != "::1" and
  not cidrmatch(destination.ip,
    "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.0.0/29", "192.0.0.8/32",
    "192.0.0.9/32", "192.0.0.10/32", "192.0.0.170/32", "192.0.0.171/32", "192.0.2.0/24", "192.31.196.0/24",
    "192.52.193.0/24", "192.168.0.0/16", "192.88.99.0/24", "224.0.0.0/4", "100.64.0.0/10", "192.175.48.0/24",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::1", "FE80::/10", "FF00::/8")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: AppleScript
    * ID: T1059.002
    * Reference URL: [https://attack.mitre.org/techniques/T1059/002/](https://attack.mitre.org/techniques/T1059/002/)

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Ingress Tool Transfer
    * ID: T1105
    * Reference URL: [https://attack.mitre.org/techniques/T1105/](https://attack.mitre.org/techniques/T1105/)



