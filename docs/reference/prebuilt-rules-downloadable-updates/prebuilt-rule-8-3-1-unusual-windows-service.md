---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-unusual-windows-service.html
---

# Unusual Windows Service [prebuilt-rule-8-3-1-unusual-windows-service]

A machine learning job detected an unusual Windows service, This can indicate execution of unauthorized services, malware, or persistence mechanisms. In corporate Windows environments, hosts do not generally run many rare or unique services. This job helps detect malware and persistence mechanisms that have been installed and run as a service.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [/reference/security/prebuilt-jobs.md](/reference/prebuilt-jobs.md)

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* ML
* Persistence

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Create or Modify System Process
    * ID: T1543
    * Reference URL: [https://attack.mitre.org/techniques/T1543/](https://attack.mitre.org/techniques/T1543/)

* Sub-technique:

    * Name: Windows Service
    * ID: T1543.003
    * Reference URL: [https://attack.mitre.org/techniques/T1543/003/](https://attack.mitre.org/techniques/T1543/003/)


