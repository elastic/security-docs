---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-5-1-binary-executed-from-shared-memory-directory.html
---

# Binary Executed from Shared Memory Directory [prebuilt-rule-8-5-1-binary-executed-from-shared-memory-directory]

Identifies the execution of a binary by root in Linux shared memory directories: (/dev/shm/, /run/shm/, /var/run/, /var/lock/). This activity is to be considered highly abnormal and should be investigated. Threat actors have placed executables used for persistence on high-uptime servers in these directories as system backdoors.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://linuxsecurity.com/features/fileless-malware-on-linux](https://linuxsecurity.com/features/fileless-malware-on-linux)
* [https://twitter.com/GossiTheDog/status/1522964028284411907](https://twitter.com/GossiTheDog/status/1522964028284411907)
* [https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor](https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Execution
* BPFDoor
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4449]

```js
process where event.type == "start" and
    event.action : ("exec", "exec_event") and user.name == "root" and
    process.executable : (
        "/dev/shm/*",
        "/run/shm/*",
        "/var/run/*",
        "/var/lock/*"
    ) and
    not process.executable : ( "/var/run/docker/*")
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



