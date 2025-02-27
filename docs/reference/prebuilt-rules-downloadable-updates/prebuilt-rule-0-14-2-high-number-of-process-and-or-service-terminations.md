---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-high-number-of-process-and-or-service-terminations.html
---

# High Number of Process and/or Service Terminations [prebuilt-rule-0-14-2-high-number-of-process-and-or-service-terminations]

This rule identifies a high number (10) of process terminations (stop, delete, or suspend) from the same host within a short time period.

**Rule type**: threshold

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Impact

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1459]

```js
event.category:process and event.type:start and process.name:(net.exe or sc.exe or taskkill.exe) and
 process.args:(stop or pause or delete or "/PID" or "/IM" or "/T" or "/F" or "/t" or "/f" or "/im" or "/pid")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Service Stop
    * ID: T1489
    * Reference URL: [https://attack.mitre.org/techniques/T1489/](https://attack.mitre.org/techniques/T1489/)



