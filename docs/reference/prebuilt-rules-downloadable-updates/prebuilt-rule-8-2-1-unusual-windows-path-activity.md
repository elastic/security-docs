---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-unusual-windows-path-activity.html
---

# Unusual Windows Path Activity [prebuilt-rule-8-2-1-unusual-windows-path-activity]

Identifies processes started from atypical folders in the file system, which might indicate malware execution or persistence mechanisms. In corporate Windows environments, software installation is centrally managed and it is unusual for programs to be executed from user or temporary directories. Processes executed from these locations can denote that a user downloaded software directly from the Internet or a malicious script or macro executed malware.

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

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

