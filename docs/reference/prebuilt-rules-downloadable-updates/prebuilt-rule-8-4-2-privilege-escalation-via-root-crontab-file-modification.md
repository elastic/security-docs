---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-privilege-escalation-via-root-crontab-file-modification.html
---

# Privilege Escalation via Root Crontab File Modification [prebuilt-rule-8-4-2-privilege-escalation-via-root-crontab-file-modification]

Identifies modifications to the root crontab file. Adversaries may overwrite this file to gain code execution with root privileges by exploiting privileged file write or move related vulnerabilities.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://phoenhex.re/2017-06-09/pwn2own-diskarbitrationd-privesc](https://phoenhex.re/2017-06-09/pwn2own-diskarbitrationd-privesc)
* [https://www.exploit-db.com/exploits/42146](https://www.exploit-db.com/exploits/42146)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Privilege Escalation

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3958]

```js
event.category:file and not event.type:deletion and
 file.path:/private/var/at/tabs/root and not process.executable:/usr/bin/crontab
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Scheduled Task/Job
    * ID: T1053
    * Reference URL: [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

* Sub-technique:

    * Name: Cron
    * ID: T1053.003
    * Reference URL: [https://attack.mitre.org/techniques/T1053/003/](https://attack.mitre.org/techniques/T1053/003/)



