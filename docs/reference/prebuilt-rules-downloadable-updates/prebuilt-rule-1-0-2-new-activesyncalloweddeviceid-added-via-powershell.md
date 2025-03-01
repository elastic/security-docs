---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-new-activesyncalloweddeviceid-added-via-powershell.html
---

# New ActiveSyncAllowedDeviceID Added via PowerShell [prebuilt-rule-1-0-2-new-activesyncalloweddeviceid-added-via-powershell]

Identifies the use of the Exchange PowerShell cmdlet Set-CASMailbox to add a new ActiveSync allowed device. Adversaries may target user email to collect sensitive information.

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

* [https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/](https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/)
* [https://docs.microsoft.com/en-us/powershell/module/exchange/set-casmailbox?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/set-casmailbox?view=exchange-ps)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Persistence

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1639]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1894]

```js
process where event.type in ("start", "process_started") and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "Set-CASMailbox*ActiveSyncAllowedDeviceIDs*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Account Manipulation
    * ID: T1098
    * Reference URL: [https://attack.mitre.org/techniques/T1098/](https://attack.mitre.org/techniques/T1098/)

* Sub-technique:

    * Name: Exchange Email Delegate Permissions
    * ID: T1098.002
    * Reference URL: [https://attack.mitre.org/techniques/T1098/002/](https://attack.mitre.org/techniques/T1098/002/)



