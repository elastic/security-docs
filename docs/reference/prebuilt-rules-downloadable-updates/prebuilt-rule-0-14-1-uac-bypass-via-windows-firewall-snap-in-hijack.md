---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-1-uac-bypass-via-windows-firewall-snap-in-hijack.html
---

# UAC Bypass via Windows Firewall Snap-In Hijack [prebuilt-rule-0-14-1-uac-bypass-via-windows-firewall-snap-in-hijack]

Identifies attempts to bypass User Account Control (UAC) by hijacking the Microsoft Management Console (MMC) Windows Firewall snap-in. Attackers bypass UAC to stealthily execute code with elevated permissions.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/AzAgarampur/byeintegrity-uac](https://github.com/AzAgarampur/byeintegrity-uac)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Privilege Escalation

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1384]

```js
process where event.type in ("start", "process_started") and
 process.parent.name == "mmc.exe" and
 /* process.Ext.token.integrity_level_name == "high" can be added in future for tuning */
 /* args of the Windows Firewall SnapIn */
  process.parent.args == "WF.msc" and process.name != "WerFault.exe"
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



