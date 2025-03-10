---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-5-1-reverse-shell-created-via-named-pipe.html
---

# Reverse Shell Created via Named Pipe [prebuilt-rule-8-5-1-reverse-shell-created-via-named-pipe]

Identifies a reverse shell via the abuse of named pipes on Linux with the help of OpenSSL or Netcat. First in, first out (FIFO) files are special files for reading and writing to by Linux processes. For this to work, a named pipe is created and passed to a Linux shell where the use of a network connection tool such as Netcat or OpenSSL has been established. The stdout and stderr are captured in the named pipe from the network connection and passed back to the shell for execution.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://int0x33.medium.com/day-43-reverse-shell-with-openssl-1ee2574aa998](https://int0x33.medium.com/day-43-reverse-shell-with-openssl-1ee2574aa998)
* [https://blog.gregscharf.com/2021/03/22/tar-in-cronjob-to-privilege-escalation/](https://blog.gregscharf.com/2021/03/22/tar-in-cronjob-to-privilege-escalation/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#openssl](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#openssl)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Execution
* Investigation Guide
* Elastic Endgame

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4451]

```js
sequence by host.id with maxspan = 5s
    [process where event.type == "start" and process.executable : ("/usr/bin/mkfifo","/usr/bin/mknod") and process.args:("/tmp/*","$*")]
    [process where process.executable : ("/bin/sh","/bin/bash") and process.args:("-i") or
        (process.executable: ("/usr/bin/openssl") and process.args: ("-connect"))]
    [process where (process.name:("nc","ncat","netcat","netcat.openbsd","netcat.traditional") or
                    (process.name: "openssl" and process.executable: "/usr/bin/openssl"))]
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

    * Name: Unix Shell
    * ID: T1059.004
    * Reference URL: [https://attack.mitre.org/techniques/T1059/004/](https://attack.mitre.org/techniques/T1059/004/)



