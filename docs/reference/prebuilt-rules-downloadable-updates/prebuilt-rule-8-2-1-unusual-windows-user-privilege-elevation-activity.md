---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-unusual-windows-user-privilege-elevation-activity.html
---

# Unusual Windows User Privilege Elevation Activity [prebuilt-rule-8-2-1-unusual-windows-user-privilege-elevation-activity]

A machine learning job detected an unusual user context switch, using the runas command or similar techniques, which can indicate account takeover or privilege escalation using compromised accounts. Privilege elevation using tools like runas are more commonly used by domain and network administrators than by regular Windows users.

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

