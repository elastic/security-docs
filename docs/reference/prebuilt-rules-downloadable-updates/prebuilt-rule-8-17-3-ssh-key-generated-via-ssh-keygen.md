---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-3-ssh-key-generated-via-ssh-keygen.html
---

# SSH Key Generated via ssh-keygen [prebuilt-rule-8-17-3-ssh-key-generated-via-ssh-keygen]

This rule identifies the creation of SSH keys using the ssh-keygen tool, which is the standard utility for generating SSH keys. Users often create SSH keys for authentication with remote services. However, threat actors can exploit this tool to move laterally across a network or maintain persistence by generating unauthorized SSH keys, granting them SSH access to systems.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.file*
* endgame-*
* logs-sentinel_one_cloud_funnel.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/primer-on-persistence-mechanisms](https://www.elastic.co/security-labs/primer-on-persistence-mechanisms)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Lateral Movement
* Tactic: Persistence
* Data Source: Elastic Endgame
* Data Source: Elastic Defend
* Data Source: SentinelOne

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4945]

```js
file where host.os.type == "linux" and event.action in ("creation", "file_create_event") and
process.executable == "/usr/bin/ssh-keygen" and file.path : ("/home/*/.ssh/*", "/root/.ssh/*", "/etc/ssh/*") and
not file.name : "known_hosts.*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: SSH Authorized Keys
    * ID: T1098.004
    * Reference URL: [https://attack.mitre.org/techniques/T1098/004/](https://attack.mitre.org/techniques/T1098/004/)

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Remote Services
    * ID: T1021
    * Reference URL: [https://attack.mitre.org/techniques/T1021/](https://attack.mitre.org/techniques/T1021/)

* Sub-technique:

    * Name: SSH
    * ID: T1021.004
    * Reference URL: [https://attack.mitre.org/techniques/T1021/004/](https://attack.mitre.org/techniques/T1021/004/)

* Technique:

    * Name: Remote Service Session Hijacking
    * ID: T1563
    * Reference URL: [https://attack.mitre.org/techniques/T1563/](https://attack.mitre.org/techniques/T1563/)

* Sub-technique:

    * Name: SSH Hijacking
    * ID: T1563.001
    * Reference URL: [https://attack.mitre.org/techniques/T1563/001/](https://attack.mitre.org/techniques/T1563/001/)



