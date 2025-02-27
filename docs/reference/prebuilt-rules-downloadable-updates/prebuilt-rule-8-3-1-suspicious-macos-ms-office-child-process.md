---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-suspicious-macos-ms-office-child-process.html
---

# Suspicious macOS MS Office Child Process [prebuilt-rule-8-3-1-suspicious-macos-ms-office-child-process]

Identifies suspicious child processes of frequently targeted Microsoft Office applications (Word, PowerPoint, and Excel). These child processes are often launched during exploitation of Office applications or by documents with malicious macros.

**Rule type**: eql

**Rule indices**:

* logs-endpoint.events.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.malwarebytes.com/cybercrime/2017/02/microsoft-office-macro-malware-targets-macs/](https://blog.malwarebytes.com/cybercrime/2017/02/microsoft-office-macro-malware-targets-macs/)

**Tags**:

* Elastic
* Host
* macOS
* Threat Detection
* Initial Access

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Rule query [_rule_query_2641]

```js
process where event.type in ("start", "process_started") and
 process.parent.name:("Microsoft Word", "Microsoft PowerPoint", "Microsoft Excel") and
 process.name:
 (
   "bash",
   "dash",
   "sh",
   "tcsh",
   "csh",
   "zsh",
   "ksh",
   "fish",
   "python*",
   "perl*",
   "php*",
   "osascript",
   "pwsh",
   "curl",
   "wget",
   "cp",
   "mv",
   "base64",
   "launchctl"
  ) and
  /* noisy false positives related to product version discovery and office errors reporting */
  not process.args:
    (
      "ProductVersion",
      "hw.model",
      "ioreg",
      "ProductName",
      "ProductUserVisibleVersion",
      "ProductBuildVersion",
      "/Library/Application Support/Microsoft/MERP*/Microsoft Error Reporting.app/Contents/MacOS/Microsoft Error Reporting"
    )
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: Phishing
    * ID: T1566
    * Reference URL: [https://attack.mitre.org/techniques/T1566/](https://attack.mitre.org/techniques/T1566/)

* Sub-technique:

    * Name: Spearphishing Attachment
    * ID: T1566.001
    * Reference URL: [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)



