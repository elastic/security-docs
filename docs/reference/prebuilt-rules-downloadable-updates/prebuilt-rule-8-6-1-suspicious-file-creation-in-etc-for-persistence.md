---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-6-1-suspicious-file-creation-in-etc-for-persistence.html
---

# Suspicious File Creation in /etc for Persistence [prebuilt-rule-8-6-1-suspicious-file-creation-in-etc-for-persistence]

Detects the manual creation of files in specific etc directories, via user root, used by Linux malware to persist and elevate privileges on compromised systems. File creation in these directories should not be entirely common and could indicate a malicious binary or script installing persistence for long term access.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* endgame-*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.intezer.com/blog/incident-response/orbit-new-undetected-linux-threat/](https://www.intezer.com/blog/incident-response/orbit-new-undetected-linux-threat/)
* [https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/](https://www.intezer.com/blog/research/lightning-framework-new-linux-threat/)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Persistence
* Orbit
* Lightning Framework
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4584]

```js
file where event.type == "creation" and user.name == "root" and
file.path : ("/etc/ld.so.conf.d/*", "/etc/cron.d/*", "/etc/sudoers.d/*", "/etc/rc.d/init.d/*", "/etc/systemd/system/*")
and not process.executable : ("*/dpkg", "*/yum", "*/apt", "*/dnf", "*/systemd", "*/snapd", "*/dnf-automatic",
 "*/yum-cron", "*/elastic-agent", "*/dnfdaemon-system")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Boot or Logon Initialization Scripts
    * ID: T1037
    * Reference URL: [https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)

* Sub-technique:

    * Name: RC Scripts
    * ID: T1037.004
    * Reference URL: [https://attack.mitre.org/techniques/T1037/004/](https://attack.mitre.org/techniques/T1037/004/)

* Technique:

    * Name: Hijack Execution Flow
    * ID: T1574
    * Reference URL: [https://attack.mitre.org/techniques/T1574/](https://attack.mitre.org/techniques/T1574/)

* Sub-technique:

    * Name: Dynamic Linker Hijacking
    * ID: T1574.006
    * Reference URL: [https://attack.mitre.org/techniques/T1574/006/](https://attack.mitre.org/techniques/T1574/006/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Systemd Service
    * ID: T1543.002
    * Reference URL: [https://attack.mitre.org/techniques/T1543/002/](https://attack.mitre.org/techniques/T1543/002/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Cron
    * ID: T1053.003
    * Reference URL: [https://attack.mitre.org/techniques/T1053/003/](https://attack.mitre.org/techniques/T1053/003/)

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



