---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-netcat-network-activity.html
---

# Netcat Network Activity [prebuilt-rule-8-2-1-netcat-network-activity]

A netcat process is engaging in network activity on a Linux host. Netcat is often used as a persistence mechanism by exporting a reverse shell or by serving a shell on a listening port. Netcat is also sometimes used for data exfiltration.

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

* [http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
* [https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf](https://www.sans.org/security-resources/sec560/netcat_cheat_sheet_v1.pdf)
* [https://en.wikipedia.org/wiki/Netcat](https://en.wikipedia.org/wiki/Netcat)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Execution

**Version**: 8

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2549]

```js
sequence by process.entity_id
  [process where (process.name == "nc" or process.name == "ncat" or process.name == "netcat" or
                  process.name == "netcat.openbsd" or process.name == "netcat.traditional") and
     event.type == "start"]
  [network where (process.name == "nc" or process.name == "ncat" or process.name == "netcat" or
                  process.name == "netcat.openbsd" or process.name == "netcat.traditional")]
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



