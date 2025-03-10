---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-7-1-potential-openssh-backdoor-logging-activity.html
---

# Potential OpenSSH Backdoor Logging Activity [prebuilt-rule-8-7-1-potential-openssh-backdoor-logging-activity]

Identifies a Secure Shell (SSH) client or server process creating or writing to a known SSH backdoor log file. Adversaries may modify SSH related binaries for persistence or credential access via patching sensitive functions to enable unauthorized access or to log SSH credentials for exfiltration.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*
* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/eset/malware-ioc/tree/master/sshdoor](https://github.com/eset/malware-ioc/tree/master/sshdoor)
* [https://www.welivesecurity.com/wp-content/uploads/2021/01/ESET_Kobalos.pdf](https://www.welivesecurity.com/wp-content/uploads/2021/01/ESET_Kobalos.pdf)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Persistence
* Credential Access
* Elastic Endgame

**Version**: 102

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3818]



## Rule query [_rule_query_4687]

```js
file where event.type == "change" and process.executable : ("/usr/sbin/sshd", "/usr/bin/ssh") and
  (
    (file.name : (".*", "~*", "*~") and not file.name : (".cache", ".viminfo", ".bash_history")) or
    file.extension : ("in", "out", "ini", "h", "gz", "so", "sock", "sync", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9") or
    file.path :
    (
      "/private/etc/*--",
      "/usr/share/*",
      "/usr/include/*",
      "/usr/local/include/*",
      "/private/tmp/*",
      "/private/var/tmp/*",
      "/usr/tmp/*",
      "/usr/share/man/*",
      "/usr/local/share/*",
      "/usr/lib/*.so.*",
      "/private/etc/ssh/.sshd_auth",
      "/usr/bin/ssd",
      "/private/var/opt/power",
      "/private/etc/ssh/ssh_known_hosts",
      "/private/var/html/lol",
      "/private/var/log/utmp",
      "/private/var/lib",
      "/var/run/sshd/sshd.pid",
      "/var/run/nscd/ns.pid",
      "/var/run/udev/ud.pid",
      "/var/run/udevd.pid"
    )
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Compromise Client Software Binary
    * ID: T1554
    * Reference URL: [https://attack.mitre.org/techniques/T1554/](https://attack.mitre.org/techniques/T1554/)



