---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-4-2-remote-ssh-login-enabled-via-systemsetup-command.html
---

# Remote SSH Login Enabled via systemsetup Command [prebuilt-rule-8-4-2-remote-ssh-login-enabled-via-systemsetup-command]

Detects use of the systemsetup command to enable remote SSH Login.

**Rule type**: query

**Rule indices**:

* auditbeat-*
* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://documents.trendmicro.com/assets/pdf/XCSSET_Technical_Brief.pdf](https://documents.trendmicro.com/assets/pdf/XCSSET_Technical_Brief.pdf)
* [https://ss64.com/osx/systemsetup.html](https://ss64.com/osx/systemsetup.md)
* [https://support.apple.com/guide/remote-desktop/about-systemsetup-apd95406b8d/mac](https://support.apple.com/guide/remote-desktop/about-systemsetup-apd95406b8d/mac)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Lateral Movement

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3929]

```js
event.category:process and event.type:(start or process_started) and
 process.name:systemsetup and
 process.args:("-setremotelogin" and on) and
 not process.parent.executable : /usr/local/jamf/bin/jamf
```

**Framework**: MITRE ATT&CKTM

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



