---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-windows-defender-exclusions-added-via-powershell.html
---

# Microsoft Defender Exclusions Added via PowerShell [prebuilt-rule-1-0-2-windows-defender-exclusions-added-via-powershell]

Identifies modifications to the Microsoft Defender configuration settings using PowerShell to add exclusions at the folder, directory, or process level.

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

**Version**: 7

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1533]

## Triage and analysis

## Investigating Windows Defender Exclusions Added via PowerShell

Microsoft Windows Defender is an antivirus product built into Microsoft Windows. Since this software product is
used to prevent and stop malware, it's important to monitor what specific exclusions are made to the product's configuration
settings. These can often be signs of an adversary or malware trying to bypass Windows Defender's capabilities. One of
the more notable [examples](https://www.cyberbit.com/blog/endpoint-security/latest-trickbot-variant-has-new-tricks-up-its-sleeve/)
was observed in 2018 where Trickbot incorporated mechanisms to disable Windows Defender to avoid detection.

### Possible investigation steps

- Investigate the process execution chain (parent process tree).
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the account owner and confirm whether they are aware of this activity.
- Examine the exclusion in order to determine the intent behind it.
- Check for similar behavior in other hosts on the environment.
- If the exclusion specifies a suspicious file, retrieve it and determine if it is malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled tasks creation.
  - Use the PowerShell Get-FileHash cmdlet to get the SHA-256 hash value of the file.
    - Search for the existence and reputation of this file in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This rule has a high chance to produce false positives due to how often network administrators legitimately configure
exclusions. In order to validate the activity further, review the specific exclusion and its intent. There are many
legitimate reasons for exclusions, so it's important to gain context.

## Related rules

- Windows Defender Disabled via Registry Modification - 2ffa1f1e-b6db-47fa-994b-1512743847eb
- Disabling Windows Defender Security Settings via PowerShell - c8cccb06-faf2-4cd5-886e-2c9636cfcb87

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Isolate the involved host to prevent further post-compromise behavior.
- If the triage identified malware, search the environment for additional compromised hosts.
  - Implement any temporary network rules, procedures, and segmentation required to contain the malware.
    - Immediately block the identified indicators of compromise (IoCs).
    - Remove and block malicious artifacts identified on the triage.
- Exclusion lists for antimalware capabilities should always be routinely monitored for review.

## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1771]

```js
process where event.type == "start" and
 (process.name : ("powershell.exe", "pwsh.exe", "powershell_ise.exe") or process.pe.original_file_name in ("powershell.exe", "pwsh.dll", "powershell_ise.exe")) and
  process.args : ("*Add-MpPreference*", "*Set-MpPreference*") and
  process.args : ("*-Exclusion*")
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



