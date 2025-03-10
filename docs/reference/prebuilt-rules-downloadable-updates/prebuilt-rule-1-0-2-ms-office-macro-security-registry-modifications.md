---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-1-0-2-ms-office-macro-security-registry-modifications.html
---

# MS Office Macro Security Registry Modifications [prebuilt-rule-1-0-2-ms-office-macro-security-registry-modifications]

Microsoft Office products offer options for users and developers to control the security settings for running and using macros. Adversaries may abuse these security settings to modify the default behavior of the Microsoft Office application to trust future macros and/or disable security warnings, which could increase their chances of establishing persistence.

**Rule type**: eql

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

**Version**: 2

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_1371]

## Triage and analysis

## Investigating MS Office Macro Security Registry Modifications

Macros are small programs that are used to automate repetitive tasks in Microsoft Office applications.
Historically, macros have been used for a variety of reasons -- from automating part of a job, to
building entire processes and data flows. Macros are written in Visual Basic for Applications (VBA) and are saved as
part of Microsoft Office files.

Macros are often created for legitimate reasons, but they can also be written by attackers to gain access, harm a
system, or bypass other security controls such as application allow listing. In fact, exploitation from malicious macros
is one of the top ways that organizations are compromised today. These attacks are often conducted through phishing or
spear phishing campaigns.

Attackers can convince victims to modify Microsoft Office security settings, so their macros are trusted by default and
no warnings are displayed when they are executed. These settings include:

* *Trust access to the VBA project object model* - When enabled, Microsoft Office will trust all macros and run any code
without showing a security warning or requiring user permission.
* *VbaWarnings* - When set to 1, Microsoft Office will trust all macros and run any code without showing a security
warning or requiring user permission.

This rule looks for registry changes affecting the conditions above.

### Possible investigation steps

- Identify the user that performed the operation.
- Verify whether malicious macros were executed after the registry change.
- Contact the user and check if the change was done manually.
- Investigate other alerts associated with the user during the past 48 hours.

## False positive analysis

- This activity should not happen legitimately. The security team should address any potential benign true
positives (B-TPs), as this configuration can put the user and the domain at risk.

## Response and remediation

- Initiate the incident response process based on the outcome of the triage.
- Reset the registry key value.
- Isolate the host if malicious code was executed and reset the involved account's passwords.
- Explore using GPOs to manage security settings for Microsoft Office macros.


## Config

If enabling an EQL rule on a non-elastic-agent index (such as beats) for versions <8.2, events will not define `event.ingested` and default fallback for EQL rules was not added until 8.2, so you will need to add a custom pipeline to populate `event.ingested` to @timestamp for this rule to work.

## Rule query [_rule_query_1600]

```js
registry where event.type == "change" and
    registry.path : (
        "HKU\\S-1-5-21-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\AccessVBOM",
        "HKU\\S-1-5-21-*\\SOFTWARE\\Microsoft\\Office\\*\\Security\\VbaWarnings"
        ) and
    registry.data.strings == "0x00000001" and
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



