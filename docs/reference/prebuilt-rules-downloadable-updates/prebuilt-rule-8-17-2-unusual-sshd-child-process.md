---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-2-unusual-sshd-child-process.html
---

# Unusual SSHD Child Process [prebuilt-rule-8-17-2-unusual-sshd-child-process]

This rule detects the creation of an unusual SSHD child process through the usage of the `new_terms` rule type. Attackers may abuse SSH to maintain persistence on a compromised system, or to establish a backdoor for remote access, potentially resulting in an unusual SSHD child process being created.

**Rule type**: new_terms

**Rule indices**:

* logs-endpoint.events.process*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://hadess.io/the-art-of-linux-persistence/](https://hadess.io/the-art-of-linux-persistence/)

**Tags**:

* Domain: Endpoint
* OS: Linux
* Use Case: Threat Detection
* Tactic: Persistence
* Data Source: Elastic Defend

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4808]

```js
event.category:process and host.os.type:linux and event.type:start and event.action:exec and
process.parent.name:(ssh or sshd) and process.args_count:2 and
not process.command_line:(-bash or -zsh or -sh)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Event Triggered Execution
    * ID: T1546
    * Reference URL: [https://attack.mitre.org/techniques/T1546/](https://attack.mitre.org/techniques/T1546/)

* Sub-technique:

    * Name: Unix Shell Configuration Modification
    * ID: T1546.004
    * Reference URL: [https://attack.mitre.org/techniques/T1546/004/](https://attack.mitre.org/techniques/T1546/004/)

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

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)



