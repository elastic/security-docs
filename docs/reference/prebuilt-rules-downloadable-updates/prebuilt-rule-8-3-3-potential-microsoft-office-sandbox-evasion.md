---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-potential-microsoft-office-sandbox-evasion.html
---

# Potential Microsoft Office Sandbox Evasion [prebuilt-rule-8-3-3-potential-microsoft-office-sandbox-evasion]

Identifies the creation of a suspicious zip file prepended with special characters. Sandboxed Microsoft Office applications on macOS are allowed to write files that start with special characters, which can be combined with an AutoStart location to achieve sandbox evasion.

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

* [https://i.blackhat.com/USA-20/Wednesday/us-20-Wardle-Office-Drama-On-macOS.pdf](https://i.blackhat.com/USA-20/Wednesday/us-20-Wardle-Office-Drama-On-macOS.pdf)
* [https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/)
* [https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Defense Evasion

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_3426]

```js
event.category:file and not event.type:deletion and file.name:~$*.zip and host.os.type:macos
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Virtualization/Sandbox Evasion
    * ID: T1497
    * Reference URL: [https://attack.mitre.org/techniques/T1497/](https://attack.mitre.org/techniques/T1497/)



