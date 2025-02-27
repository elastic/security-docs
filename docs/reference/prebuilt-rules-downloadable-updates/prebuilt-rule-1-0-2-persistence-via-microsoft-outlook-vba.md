---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-persistence-via-microsoft-outlook-vba.html
---

# Persistence via Microsoft Outlook VBA [prebuilt-rule-1-0-2-persistence-via-microsoft-outlook-vba]

Detects attempts to establish persistence on an endpoint by installing a rogue Microsoft Outlook VBA Template.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*
* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/](https://www.mdsec.co.uk/2020/11/a-fresh-outlook-on-mail-based-persistence/)
* [https://www.linkedin.com/pulse/outlook-backdoor-using-vba-samir-b-/](https://www.linkedin.com/pulse/outlook-backdoor-using-vba-samir-b-/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1638]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1893]

```js
file where event.type != "deletion" and
 file.path : "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Outlook\\VbaProject.OTM"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Office Application Startup
    * ID: T1137
    * Reference URL: [https://attack.mitre.org/techniques/T1137/](https://attack.mitre.org/techniques/T1137/)



