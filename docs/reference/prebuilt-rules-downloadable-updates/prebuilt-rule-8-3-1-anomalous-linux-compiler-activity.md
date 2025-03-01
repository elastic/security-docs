---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-anomalous-linux-compiler-activity.html
---

# Anomalous Linux Compiler Activity [prebuilt-rule-8-3-1-anomalous-linux-compiler-activity]

Looks for compiler activity by a user context which does not normally run compilers. This can be the result of ad-hoc software changes or unauthorized software deployment. This can also be due to local privilege elevation via locally run exploits or malware activity.

**Rule type**: machine_learning

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 15m

**Searches indices from**: now-45m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**: None

**Tags**:

* Elastic
* Host
* Linux
* Threat Detection
* ML
* Resource Development

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Resource Development
    * ID: TA0042
    * Reference URL: [https://attack.mitre.org/tactics/TA0042/](https://attack.mitre.org/tactics/TA0042/)

* Technique:

    * Name: Obtain Capabilities
    * ID: T1588
    * Reference URL: [https://attack.mitre.org/techniques/T1588/](https://attack.mitre.org/techniques/T1588/)

* Sub-technique:

    * Name: Malware
    * ID: T1588.001
    * Reference URL: [https://attack.mitre.org/techniques/T1588/001/](https://attack.mitre.org/techniques/T1588/001/)


