---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-potential-non-standard-port-ssh-connection.html
---

# Potential Non-Standard Port SSH connection [prebuilt-rule-8-4-1-potential-non-standard-port-ssh-connection]

Identifies potentially malicious processes communicating via a port paring typically not associated with SSH. For example, SSH over port 2200 or port 2222 as opposed to the traditional port 22. Adversaries may make changes to the standard port a protocol uses to bypass filtering or muddle analysis/parsing of network data.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://attack.mitre.org/techniques/T1571/](https://attack.mitre.org/techniques/T1571/)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Command and Control
* macOS

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2950]

```js
sequence by process.entity_id with maxspan=1m
[process where event.action == "exec" and process.name:"ssh"]
[network where process.name:"ssh"
 and event.action in ("connection_attempted", "connection_accepted")
 and destination.port != 22
 and destination.ip != "127.0.0.1"
 and network.transport: "tcp"
]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Non-Standard Port
    * ID: T1571
    * Reference URL: [https://attack.mitre.org/techniques/T1571/](https://attack.mitre.org/techniques/T1571/)



