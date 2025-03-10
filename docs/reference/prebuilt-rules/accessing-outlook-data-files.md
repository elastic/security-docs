---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/accessing-outlook-data-files.html
---

# Accessing Outlook Data Files [accessing-outlook-data-files]

Identifies commands containing references to Outlook data files extensions, which can potentially indicate the search, access, or modification of these files.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.process-*
* logs-windows.sysmon_operational-*
* endgame-*
* logs-system.security*
* winlogbeat-*

**Severity**: low

**Risk score**: 21

**Runs every**: 60m

**Searches indices from**: now-119m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Domain: Endpoint
* OS: Windows
* Use Case: Threat Detection
* Tactic: Collection
* Data Source: Elastic Defend
* Rule Type: BBR
* Data Source: Sysmon
* Data Source: Elastic Endgame
* Data Source: System

**Version**: 105

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_120]

```js
process where host.os.type == "windows" and event.type == "start" and process.args : ("*.ost", "*.pst") and
  not process.name : "outlook.exe" and
  not (
        process.name : "rundll32.exe" and
        process.args : "*davclnt.dll,DavSetCookie*"
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Email Collection
    * ID: T1114
    * Reference URL: [https://attack.mitre.org/techniques/T1114/](https://attack.mitre.org/techniques/T1114/)

* Sub-technique:

    * Name: Local Email Collection
    * ID: T1114.001
    * Reference URL: [https://attack.mitre.org/techniques/T1114/001/](https://attack.mitre.org/techniques/T1114/001/)



