---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-powershell-suspicious-payload-encoded-and-compressed.html
---

# PowerShell Suspicious Payload Encoded and Compressed [prebuilt-rule-1-0-2-powershell-suspicious-payload-encoded-and-compressed]

Identifies the use of .NET functionality for decompression and base64 decoding combined in PowerShell scripts, which malware and security tools heavily use to deobfuscate payloads and load them directly in memory to bypass defenses.

**Rule type**: query

**Rule indices**:

* winlogbeat-*
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
* Defense Evasion

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_1798]

```js
event.category:process and
  powershell.file.script_block_text : (
    (
      "System.IO.Compression.DeflateStream" or
      "System.IO.Compression.GzipStream" or
      "IO.Compression.DeflateStream" or
      "IO.Compression.GzipStream"
    ) and
    FromBase64String
  )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Deobfuscate/Decode Files or Information
    * ID: T1140
    * Reference URL: [https://attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/)

* Technique:

    * Name: Obfuscated Files or Information
    * ID: T1027
    * Reference URL: [https://attack.mitre.org/techniques/T1027/](https://attack.mitre.org/techniques/T1027/)

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



