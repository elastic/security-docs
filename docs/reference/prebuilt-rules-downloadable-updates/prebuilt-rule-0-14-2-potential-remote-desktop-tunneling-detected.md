---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-potential-remote-desktop-tunneling-detected.html
---

# Potential Remote Desktop Tunneling Detected [prebuilt-rule-0-14-2-potential-remote-desktop-tunneling-detected]

Identifies potential use of an SSH utility to establish RDP over a reverse SSH Tunnel. This can be used by attackers to enable routing of network packets that would otherwise not reach their intended destination.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.netspi.com/how-to-access-rdp-over-a-reverse-ssh-tunnel/](https://blog.netspi.com/how-to-access-rdp-over-a-reverse-ssh-tunnel/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Command and Control

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1418]

```js
process where event.type in ("start", "process_started") and
  /* RDP port and usual SSH tunneling related switches in command line */
  process.args : "*:3389" and
  process.args : ("-L", "-P", "-R", "-pw", "-ssh")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Protocol Tunneling
    * ID: T1572
    * Reference URL: [https://attack.mitre.org/techniques/T1572/](https://attack.mitre.org/techniques/T1572/)



