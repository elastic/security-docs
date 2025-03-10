---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-5-1-powershell-mailbox-collection-script.html
---

# PowerShell Mailbox Collection Script [prebuilt-rule-8-5-1-powershell-mailbox-collection-script]

Detects PowerShell scripts that can be used to collect data from mailboxes. Adversaries may target user email to collect sensitive information.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1](https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1)
* [https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/apt29/Archive/CALDERA_DIY/evals/payloads/stepSeventeen_email.ps1](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/blob/master/apt29/Archive/CALDERA_DIY/evals/payloads/stepSeventeen_email.ps1)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* Collection
* PowerShell

**Version**: 1

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_4399]

```js
event.category:process and
  (
   powershell.file.script_block_text : (
      "Microsoft.Office.Interop.Outlook" or
      "Interop.Outlook.olDefaultFolders" or
      "::olFolderInBox"
   ) or
   powershell.file.script_block_text : (
      "Microsoft.Exchange.WebServices.Data.Folder" or
      "Microsoft.Exchange.WebServices.Data.FileAttachment"
   )
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

* Sub-technique:

    * Name: Remote Email Collection
    * ID: T1114.002
    * Reference URL: [https://attack.mitre.org/techniques/T1114/002/](https://attack.mitre.org/techniques/T1114/002/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: Command and Scripting Interpreter
    * ID: T1059
    * Reference URL: [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

* Sub-technique:

    * Name: PowerShell
    * ID: T1059.001
    * Reference URL: [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)



