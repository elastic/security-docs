---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-1-potential-shadow-file-read-via-command-line-utilities.html
---

# Potential Shadow File Read via Command Line Utilities [prebuilt-rule-8-4-1-potential-shadow-file-read-via-command-line-utilities]

Identifies access to the /etc/shadow file via the commandline using standard system utilities. After elevating privileges to root, threat actors may attempt to read or dump this file in order to gain valid credentials. They may utilize these to move laterally undetected and access additional resources.

**Rule type**: eql

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.cyberciti.biz/faq/unix-linux-password-cracking-john-the-ripper/](https://www.cyberciti.biz/faq/unix-linux-password-cracking-john-the-ripper/)

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* Privilege Escalation
* Credential Access

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3048]

```js
process where event.type == "start" and event.action == "exec" and user.name == "root"
  and (process.args : "/etc/shadow" or (process.working_directory: "/etc" and process.args: "shadow"))
  and not process.executable:
    ("/usr/bin/tar",
    "/bin/tar",
    "/usr/bin/gzip",
    "/bin/gzip",
    "/usr/bin/zip",
    "/bin/zip",
    "/usr/bin/stat",
    "/bin/stat",
    "/usr/bin/cmp",
    "/bin/cmp",
    "/usr/bin/sudo",
    "/bin/sudo",
    "/usr/bin/find",
    "/bin/find",
    "/usr/bin/ls",
    "/bin/ls",
    "/usr/bin/uniq",
    "/bin/uniq",
    "/usr/bin/unzip",
    "/bin/unzip")
  and not process.parent.executable: "/bin/dracut"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Exploitation for Privilege Escalation
    * ID: T1068
    * Reference URL: [https://attack.mitre.org/techniques/T1068/](https://attack.mitre.org/techniques/T1068/)

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: /etc/passwd and /etc/shadow
    * ID: T1003.008
    * Reference URL: [https://attack.mitre.org/techniques/T1003/008/](https://attack.mitre.org/techniques/T1003/008/)



