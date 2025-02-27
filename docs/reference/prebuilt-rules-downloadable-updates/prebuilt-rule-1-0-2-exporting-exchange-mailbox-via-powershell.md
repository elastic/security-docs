---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-exporting-exchange-mailbox-via-powershell.html
---

# Exporting Exchange Mailbox via PowerShell [prebuilt-rule-1-0-2-exporting-exchange-mailbox-via-powershell]

Identifies the use of the Exchange PowerShell cmdlet New-MailBoxExportRequest to export the contents of a primary mailbox or archive to a .pst file. Adversaries may target user email to collect sensitive information.

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
* [https://docs.microsoft.com/en-us/powershell/module/exchange/new-mailboxexportrequest?view=exchange-ps](https://docs.microsoft.com/en-us/powershell/module/exchange/new-mailboxexportrequest?view=exchange-ps)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Collection

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1491]

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1725]

```js
process where event.type in ("start", "process_started") and
  process.name: ("powershell.exe", "pwsh.exe", "powershell_ise.exe") and process.args : "New-MailboxExportRequest*"
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Collection
    * ID: TA0009
    * Reference URL: [https://attack.mitre.org/tactics/TA0009/](https://attack.mitre.org/tactics/TA0009/)

* Technique:

    * Name: Data from Local System
    * ID: T1005
    * Reference URL: [https://attack.mitre.org/techniques/T1005/](https://attack.mitre.org/techniques/T1005/)

* Technique:

    * Name: Email Collection
    * ID: T1114
    * Reference URL: [https://attack.mitre.org/techniques/T1114/](https://attack.mitre.org/techniques/T1114/)

* Sub-technique:

    * Name: Remote Email Collection
    * ID: T1114.002
    * Reference URL: [https://attack.mitre.org/techniques/T1114/002/](https://attack.mitre.org/techniques/T1114/002/)



