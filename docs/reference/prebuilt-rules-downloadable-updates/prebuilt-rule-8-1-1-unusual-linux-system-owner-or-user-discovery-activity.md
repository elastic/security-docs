---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-1-1-unusual-linux-system-owner-or-user-discovery-activity.html
---

# Unusual Linux System Owner or User Discovery Activity [prebuilt-rule-8-1-1-unusual-linux-system-owner-or-user-discovery-activity]

Looks for commands related to system user or owner discovery from an unusual user context. This can be due to uncommon troubleshooting activity or due to a compromised account. A compromised account may be used to engage in system owner or user discovery in order to identify currently active or primary users of a system. This may be a precursor to additional discovery, credential dumping or privilege elevation activity.

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

**Version**: 3

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Owner/User Discovery
    * ID: T1033
    * Reference URL: [https://attack.mitre.org/techniques/T1033/](https://attack.mitre.org/techniques/T1033/)


