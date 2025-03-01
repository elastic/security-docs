---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-bash-shell-profile-modification.html
---

# Bash Shell Profile Modification [prebuilt-rule-8-4-2-bash-shell-profile-modification]

Both ~/.bash_profile and ~/.bashrc are files containing shell commands that are run when Bash is invoked. These files are executed in a user’s context, either interactively or non-interactively, when a user logs in so that their environment is set correctly. Adversaries may abuse this to establish persistence by executing malicious content triggered by a user’s shell.

**Rule type**: query

**Rule indices**:

* logs-endpoint.events.*
* auditbeat-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.anomali.com/blog/pulling-linux-rabbit-rabbot-malware-out-of-a-hat](https://www.anomali.com/blog/pulling-linux-rabbit-rabbot-malware-out-of-a-hat)

**Tags**:

* Elastic
* Host
* macOS
* Linux
* Threat Detection
* Persistence

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3802]

```js
event.category:file and event.type:change and
  process.name:(* and not (sudo or
                           vim or
                           zsh or
                           env or
                           nano or
                           bash or
                           Terminal or
                           xpcproxy or
                           login or
                           cat or
                           cp or
                           launchctl or
                           java)) and
  not process.executable:(/Applications/* or /private/var/folders/* or /usr/local/*) and
  file.path:(/private/etc/rc.local or
             /etc/rc.local or
             /home/*/.profile or
             /home/*/.profile1 or
             /home/*/.bash_profile or
             /home/*/.bash_profile1 or
             /home/*/.bashrc or
             /Users/*/.bash_profile or
             /Users/*/.zshenv)
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



