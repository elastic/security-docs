---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-3-1-unusual-linux-network-connection-discovery.html
---

# Unusual Linux Network Connection Discovery [prebuilt-rule-8-3-1-unusual-linux-network-connection-discovery]

Looks for commands related to system network connection discovery from an unusual user context. This can be due to uncommon troubleshooting activity or due to a compromised account. A compromised account may be used by a threat actor to engage in system network connection discovery in order to increase their understanding of connected services and systems. This information may be used to shape follow-up behaviors such as lateral movement or additional discovery.

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

**Version**: 100

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Discovery
    * ID: TA0007
    * Reference URL: [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)

* Technique:

    * Name: System Network Connections Discovery
    * ID: T1049
    * Reference URL: [https://attack.mitre.org/techniques/T1049/](https://attack.mitre.org/techniques/T1049/)


