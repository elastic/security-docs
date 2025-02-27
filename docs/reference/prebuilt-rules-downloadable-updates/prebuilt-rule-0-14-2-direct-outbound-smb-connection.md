---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-direct-outbound-smb-connection.html
---

# Direct Outbound SMB Connection [prebuilt-rule-0-14-2-direct-outbound-smb-connection]

Identifies unexpected processes making network connections over port 445. Windows File Sharing is typically implemented over Server Message Block (SMB), which communicates between hosts using port 445. When legitimate, these network connections are established by the kernel. Processes making 445/tcp connections may be port scanners, exploits, or suspicious user-level processes moving laterally.

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

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Lateral Movement

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1466]

```js
sequence by process.entity_id
  [process where event.type == "start" and process.pid != 4]
  [network where destination.port == 445 and process.pid != 4 and
     not cidrmatch(destination.ip, "127.0.0.1", "::1")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SMB/Windows Admin Shares
    * ID: T1021.002
    * Reference URL: [https://attack.mitre.org/techniques/T1021/002/](https://attack.mitre.org/techniques/T1021/002/)



