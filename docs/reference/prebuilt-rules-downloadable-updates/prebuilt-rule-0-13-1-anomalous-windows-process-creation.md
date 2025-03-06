---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-0-13-1-anomalous-windows-process-creation.html
---

# Anomalous Windows Process Creation [prebuilt-rule-0-13-1-anomalous-windows-process-creation]

Identifies unusual parent-child process relationships that can indicate malware execution or persistence mechanisms. Malicious scripts often call on other applications and processes as part of their exploit payload. For example, when a malicious Office document runs scripts as part of an exploit payload, Excel or Word may start a script interpreter process, which, in turn, runs a script that downloads and executes malware. Another common scenario is Outlook running an unusual process when malware is downloaded in an email. Monitoring and identifying anomalous process relationships is a method of detecting new and emerging malware that is not yet recognized by anti-virus scanners.

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

**version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

