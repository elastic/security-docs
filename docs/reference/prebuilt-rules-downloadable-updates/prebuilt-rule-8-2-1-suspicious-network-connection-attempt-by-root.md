---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-suspicious-network-connection-attempt-by-root.html
---

# Suspicious Network Connection Attempt by Root [prebuilt-rule-8-2-1-suspicious-network-connection-attempt-by-root]

Identifies an outbound network connection attempt followed by a session id change as the root user by the same process entity. This particular instantiation of a network connection is abnormal and should be investigated as it may indicate a potential reverse shell activity via a privileged process.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 43

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.sandflysecurity.com/blog/linux-file-masquerading-and-malicious-pids-sandfly-1-2-6-update/](https://www.sandflysecurity.com/blog/linux-file-masquerading-and-malicious-pids-sandfly-1-2-6-update/)
* [https://twitter.com/GossiTheDog/status/1522964028284411907](https://twitter.com/GossiTheDog/status/1522964028284411907)
* [https://exatrack.com/public/Tricephalic_Hellkeeper.pdf](https://exatrack.com/public/Tricephalic_Hellkeeper.pdf)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Command and Control

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_2255]

## Triage and analysis
## Investigating Connection Attempt by Non-SSH Root Session
Detection alerts from this rule indicate a strange or abnormal outbound connection attempt by a privileged process.  Here are some possible avenues of investigation:
- Examine unusual and active sessions using commands such as 'last -a', 'netstat -a', and 'w -a'.
- Analyze processes and command line arguments to detect anomalous process execution that may be acting as a listener.
- Analyze anomalies in the use of files that do not normally initiate connections.
- Examine processes utilizing the network that do not normally have network communication.

## Rule query [_rule_query_2546]

```js
sequence by process.entity_id with maxspan=1m
[network where event.type == "start" and event.action == "connection_attempted" and user.id == "0" and
    not process.executable : ("/bin/ssh", "/sbin/ssh", "/usr/lib/systemd/systemd", "/usr/sbin/sshd")]
[process where event.action == "session_id_change" and user.id == "0" and
    not process.executable : ("/bin/ssh", "/sbin/ssh", "/usr/lib/systemd/systemd", "/usr/sbin/sshd")]
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Non-Application Layer Protocol
    * ID: T1095
    * Reference URL: [https://attack.mitre.org/techniques/T1095/](https://attack.mitre.org/techniques/T1095/)

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Sudo and Sudo Caching
    * ID: T1548.003
    * Reference URL: [https://attack.mitre.org/techniques/T1548/003/](https://attack.mitre.org/techniques/T1548/003/)



