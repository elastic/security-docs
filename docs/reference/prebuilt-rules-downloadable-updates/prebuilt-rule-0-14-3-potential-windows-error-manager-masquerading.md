---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-3-potential-windows-error-manager-masquerading.html
---

# Potential Windows Error Manager Masquerading [prebuilt-rule-0-14-3-potential-windows-error-manager-masquerading]

Identifies suspicious instances of the Windows Error Reporting process (WerFault.exe or Wermgr.exe) with matching command-line and process executable values performing outgoing network connections. This may be indicative of a masquerading attempt to evade suspicious child process behavior detections.

**Rule type**: eql

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

* [https://twitter.com/SBousseaden/status/1235533224337641473](https://twitter.com/SBousseaden/status/1235533224337641473)
* [https://www.hexacorn.com/blog/2019/09/20/werfault-command-line-switches-v0-1/](https://www.hexacorn.com/blog/2019/09/20/werfault-command-line-switches-v0-1/)
* [https://app.any.run/tasks/26051d84-b68e-4afb-8a9a-76921a271b81/](https://app.any.run/tasks/26051d84-b68e-4afb-8a9a-76921a271b81/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1539]

```js
sequence by host.id, process.entity_id with maxspan = 5s
  [process where event.type:"start" and process.name : ("wermgr.exe", "WerFault.exe") and process.args_count == 1]
  [network where process.name : ("wermgr.exe", "WerFault.exe") and network.protocol != "dns" and
    network.direction : ("outgoing", "egress") and destination.ip !="::1" and destination.ip !="127.0.0.1"
  ]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Masquerading
    * ID: T1036
    * Reference URL: [https://attack.mitre.org/techniques/T1036/](https://attack.mitre.org/techniques/T1036/)



