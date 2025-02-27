---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-uac-bypass-attempt-via-windows-directory-masquerading.html
---

# UAC Bypass Attempt via Windows Directory Masquerading [prebuilt-rule-1-0-2-uac-bypass-attempt-via-windows-directory-masquerading]

Identifies an attempt to bypass User Account Control (UAC) by masquerading as a Microsoft trusted Windows directory. Attackers may bypass UAC to stealthily execute code with elevated permissions.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: high

**Risk score**: 73

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://medium.com/tenable-techblog/uac-bypass-by-mocking-trusted-directories-24a96675f6e](https://medium.com/tenable-techblog/uac-bypass-by-mocking-trusted-directories-24a96675f6e)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1673]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1940]

```js
process where event.type in ("start", "process_started") and
  process.args : ("C:\\Windows \\system32\\*.exe", "C:\\Windows \\SysWOW64\\*.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Abuse Elevation Control Mechanism
    * ID: T1548
    * Reference URL: [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

* Sub-technique:

    * Name: Bypass User Account Control
    * ID: T1548.002
    * Reference URL: [https://attack.mitre.org/techniques/T1548/002/](https://attack.mitre.org/techniques/T1548/002/)



