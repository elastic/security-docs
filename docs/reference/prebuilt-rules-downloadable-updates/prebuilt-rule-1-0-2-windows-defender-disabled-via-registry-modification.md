---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-windows-defender-disabled-via-registry-modification.html
---

# Windows Defender Disabled via Registry Modification [prebuilt-rule-1-0-2-windows-defender-disabled-via-registry-modification]

Identifies modifications to the Windows Defender registry settings to disable the service or set the service to be started manually.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://thedfirreport.com/2020/12/13/defender-control/](https://thedfirreport.com/2020/12/13/defender-control/)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Defense Evasion

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1532]

## Triage and analysis

Detections should be investigated to identify if the hosts and users are authorized to use this tool. As this rule detects post-exploitation process activity, investigations into this should be prioritized.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1770]

```js
registry where event.type in ("creation", "change") and
  (
    (
      registry.path:"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware" and
      registry.data.strings: ("1", "0x00000001")
   ) or
   (
      registry.path:"HKLM\\System\\*ControlSet*\\Services\\WinDefend\\Start" and
      registry.data.strings in ("3", "4", "0x00000003", "0x00000004")
   )
  )
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

* Sub-technique:

    * Name: Indicator Blocking
    * ID: T1562.006
    * Reference URL: [https://attack.mitre.org/techniques/T1562/006/](https://attack.mitre.org/techniques/T1562/006/)



