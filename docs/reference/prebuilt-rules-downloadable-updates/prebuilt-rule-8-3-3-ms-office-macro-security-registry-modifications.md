---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-ms-office-macro-security-registry-modifications.html
---

# MS Office Macro Security Registry Modifications [prebuilt-rule-8-3-3-ms-office-macro-security-registry-modifications]

Microsoft Office Products offer options for users and developers to control the security settings for running and using Macros. Adversaries may abuse these security settings to modify the default behavior of the Office Application to trust future macros and/or disable security warnings, which could increase their chances of establishing persistence.

**Rule type**: eql

**Rule indices**:

* winlogbeat-*
* logs-windows.*
* endgame-*

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
* Investigation Guide
* Elastic Endgame

**Version**: 103

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_3073]

## Triage and analysis

## Investigating MS Office Macro Security Registry Modifications

Macros are small programs that are used to automate repetitive tasks in Microsoft Office applications. Historically, macros have been used for a variety of reasons -- from automating part of a job, to building entire processes and data flows. Macros are written in Visual Basic for Applications (VBA) and are saved as part of Microsoft Office files.

Macros are often created for legitimate reasons, but they can also be written by attackers to gain access, harm a system, or bypass other security controls such as application allow listing. In fact, exploitation from malicious macros is one of the top ways that organizations are compromised today. These attacks are often conducted through phishing or spear phishing campaigns.

Attackers can convince victims to modify Microsoft Office security settings, so their macros are trusted by default and no warnings are displayed when they are executed. These settings include:

- *Trust access to the VBA project object model* - When enabled, Microsoft Office will trust all macros and run any code without showing a security warning or requiring user permission.
- *VbaWarnings* - When set to 1, Microsoft Office will trust all macros and run any code without showing a security warning or requiring user permission.

This rule looks for registry changes affecting the conditions above.

### Possible investigation steps

- Investigate the process execution chain (parent process tree) for unknown processes. Examine their executable files for prevalence, whether they are located in expected locations, and if they are signed with valid digital signatures.
- Identify the user account that performed the action and whether it should perform this kind of action.
- Contact the user and check if the change was done manually.
- Verify whether malicious macros were executed after the registry change.
- Investigate other alerts associated with the user/host during the past 48 hours.
- Retrieve recently executed Office documents and determine if they are malicious:
  - Use a private sandboxed malware analysis system to perform analysis.
    - Observe and collect information about the following activities:
      - Attempts to contact external domains and addresses.
      - File and registry access, modification, and creation activities.
      - Service creation and launch activities.
      - Scheduled task creation.
  - Use the PowerShell Get-FileHash cmdlet to get the files' SHA-256 hash values.
    - Search for the existence and reputation of the hashes in resources like VirusTotal, Hybrid-Analysis, CISCO Talos, Any.run, etc.

## False positive analysis

- This activity should not happen legitimately. The security team should address any potential benign true positive (B-TP), as this configuration can put the user and the domain at risk.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Reset the registry key value.
- Isolate the involved host to prevent further post-compromise behavior.
- Investigate credential exposure on systems compromised or used by the attacker to ensure all compromised accounts are identified. Reset passwords for these accounts and other potentially compromised credentials, such as email, business systems, and web services.
- Explore using GPOs to manage security settings for Microsoft Office macros.
- Run a full antimalware scan. This may reveal additional artifacts left in the system, persistence mechanisms, and malware components.
- Determine the initial vector abused by the attacker and take action to prevent reinfection through the same vector.
- Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).

## Rule query [_rule_query_3576]

```js
registry where event.type == "change" and
    registry.path : (
        "HKU\\S-1-5-21-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\AccessVBOM",
        "HKU\\S-1-5-21-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\VbaWarnings",
        "HKU\\S-1-12-1-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\AccessVBOM",
        "HKU\\S-1-12-1-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\VbaWarnings",
        "\\REGISTRY\\USER\\S-1-5-21-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\AccessVBOM",
        "\\REGISTRY\\USER\\S-1-5-21-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\VbaWarnings",
        "\\REGISTRY\\USER\\S-1-12-1-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\AccessVBOM",
        "\\REGISTRY\\USER\\S-1-12-1-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\VbaWarnings"
        ) and
    registry.data.strings : ("0x00000001", "1") and
    process.name : ("cscript.exe", "wscript.exe", "mshta.exe", "mshta.exe", "winword.exe", "excel.exe")
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Modify Registry
    * ID: T1112
    * Reference URL: [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)

* Tactic:

    * Name: Execution
    * ID: TA0002
    * Reference URL: [https://attack.mitre.org/tactics/TA0002/](https://attack.mitre.org/tactics/TA0002/)

* Technique:

    * Name: User Execution
    * ID: T1204
    * Reference URL: [https://attack.mitre.org/techniques/T1204/](https://attack.mitre.org/techniques/T1204/)

* Sub-technique:

    * Name: Malicious File
    * ID: T1204.002
    * Reference URL: [https://attack.mitre.org/techniques/T1204/002/](https://attack.mitre.org/techniques/T1204/002/)



