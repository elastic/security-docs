---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-suspicious-powershell-script.html
---

# Suspicious Powershell Script [prebuilt-rule-8-2-1-suspicious-powershell-script]

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

**Tags**:

* Elastic
* Host
* Windows
* Threat Detection
* ML

**Version**: 4

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

