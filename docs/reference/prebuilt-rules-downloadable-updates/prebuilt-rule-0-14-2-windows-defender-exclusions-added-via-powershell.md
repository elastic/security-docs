---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-14-2-windows-defender-exclusions-added-via-powershell.html
---

# Windows Defender Exclusions Added via PowerShell [prebuilt-rule-0-14-2-windows-defender-exclusions-added-via-powershell]

Identifies modifications to the Windows Defender configuration settings using PowerShell to add exclusions at the folder directory or process level.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-endpoint.events.*
* logs-windows.*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.bitdefender.com/files/News/CaseStudies/study/400/Bitdefender-PR-Whitepaper-MosaicLoader-creat5540-en-EN.pdf](https://www.bitdefender.com/files/News/CaseStudies/study/400/Bitdefender-PR-Whitepaper-MosaicLoader-creat5540-en-EN.pdf)

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

## Investigation guide [_investigation_guide_1314]

## Triage and analysis

## Investigating Windows Defender Exclusions

Microsoft Windows Defender is an anti-virus product built-in within Microsoft Windows. Since this software product is
used to prevent and stop malware, it's important to monitor what specific exclusions are made to the product's configuration
settings. These can often be signs of an adversary or malware trying to bypass Windows Defender's capabilities. One of the more
notable [examples](https://www.cyberbit.com/blog/endpoint-security/latest-trickbot-variant-has-new-tricks-up-its-sleeve/) was observed in 2018 where Trickbot incorporated mechanisms to disable Windows Defense to avoid detection.

### Possible investigation steps:
- With this specific rule, it's completely possible to trigger detections on network administrative activity or benign users
using scripting and PowerShell to configure the different exclusions for Windows Defender. Therefore, it's important to
identify the source of the activity first and determine if there is any mal-intent behind the events.
- The actual exclusion such as the process, the file or directory should be reviewed in order to determine the original
intent behind the exclusion. Is the excluded file or process malicious in nature or is it related to software that needs
to be legitimately whitelisted from Windows Defender?

## False Positive Analysis
- This rule has a higher chance to produce false positives based on the nature around configuring exclusions by possibly
a network administrator. In order to validate the activity further, review the specific exclusion made and determine based
on the exclusion of the original intent behind the exclusion. There are often many legitimate reasons why exclusions are made
with Windows Defender so it's important to gain context around the exclusion.

## Related Rules
- Windows Defender Disabled via Registry Modification
- Disabling Windows Defender Security Settings via PowerShell

## Response and Remediation
- Since this is related to post-exploitation activity, immediate response should be taken to review, investigate and
potentially isolate further activity
- If further analysis showed malicious intent was behind the Defender exclusions, administrators should remove
the exclusion and ensure antimalware capability has not been disabled or deleted
- Exclusion lists for antimalware capabilities should always be routinely monitored for review

## Rule query [_rule_query_1428]

```js
process where event.type == "start" and
 (process.name : ("powershell.exe", "pwsh.exe") or process.pe.original_file_name : ("powershell.exe", "pwsh.exe")) and
  process.args : ("*Add-MpPreference*-Exclusion*", "*Set-MpPreference*-Exclusion*")
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

    * Name: Indicator Blocking
    * ID: T1562.006
    * Reference URL: [https://attack.mitre.org/techniques/T1562/006/](https://attack.mitre.org/techniques/T1562/006/)

* Sub-technique:

    * Name: Disable or Modify Tools
    * ID: T1562.001
    * Reference URL: [https://attack.mitre.org/techniques/T1562/001/](https://attack.mitre.org/techniques/T1562/001/)

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



