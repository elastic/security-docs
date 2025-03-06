---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-3-suspicious-powershell-script.html
---

# Suspicious Powershell Script [prebuilt-rule-8-3-3-suspicious-powershell-script]

A machine learning job detected a PowerShell script with unusual data characteristics, such as obfuscation, that may be a characteristic of malicious PowerShell script text blocks.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [Prebuilt anomaly detection jobs](docs-content://reference/security/prebuilt-anomaly-detection-jobs.md)
* [https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration](https://www.elastic.co/security-labs/detecting-living-off-the-land-attacks-with-new-elastic-integration)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* ML
* Execution

**Version**: 101

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

**Framework**: MITRE ATT&CKTM

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


