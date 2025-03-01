---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-1-exporting-exchange-mailbox-via-powershell.html
---

# Exporting Exchange Mailbox via PowerShell [prebuilt-rule-0-14-1-exporting-exchange-mailbox-via-powershell]

Identifies the use of the Exchange PowerShell cmdlet, New-MailBoxExportRequest, to export the contents of a primary mailbox or archive to a .pst file. Adversaries may target user email to collect sensitive information.

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

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1365]

```js
process where event.type in ("start", "process_started") and
  process.name: ("powershell.exe", "pwsh.exe") and process.args : "New-MailboxExportRequest*"
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

* Technique:

    * Name: Data from Local System
    * ID: T1005
    * Reference URL: [https://attack.mitre.org/techniques/T1005/](https://attack.mitre.org/techniques/T1005/)



