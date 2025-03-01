---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-1-potential-privacy-control-bypass-via-tccdb-modification.html
---

# Potential Privacy Control Bypass via TCCDB Modification [prebuilt-rule-0-14-1-potential-privacy-control-bypass-via-tccdb-modification]

Identifies the use of sqlite3 to directly modify the Transparency, Consent, and Control (TCC) SQLite database. This may indicate an attempt to bypass macOS privacy controls, including access to sensitive resources like the system camera, microphone, address book, and calendar.

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

* [https://applehelpwriter.com/2016/08/29/discovering-how-dropbox-hacks-your-mac/](https://applehelpwriter.com/2016/08/29/discovering-how-dropbox-hacks-your-mac/)
* [https://github.com/bp88/JSS-Scripts/blob/master/TCC.db%20Modifier.sh](https://github.com/bp88/JSS-Scripts/blob/master/TCC.db%20Modifier.sh)
* [https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8](https://medium.com/@mattshockl/cve-2020-9934-bypassing-the-os-x-transparency-consent-and-control-tcc-framework-for-4e14806f1de8)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Defense Evasion

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1351]

```js
process where event.type in ("start", "process_started") and process.name : "sqlite*" and
 process.args : "/*/Application Support/com.apple.TCC/TCC.db"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)



