---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-unusual-web-request.html
---

# Unusual Web Request [prebuilt-rule-8-2-1-unusual-web-request]

A machine learning job detected a rare and unusual URL that indicates unusual web browsing activity. This can be due to initial access, persistence, command-and-control, or exfiltration activity. For example, in a strategic web compromise or watering hole attack, when a trusted website is compromised to target a particular sector or organization, targeted users may receive emails with uncommon URLs for trusted websites. These URLs can be used to download and run a payload. When malware is already running, it may send requests to uncommon URLs on trusted websites the malware uses for command-and-control communication. When rare URLs are observed being requested for a local web server by a remote source, these can be due to web scanning, enumeration or attack traffic, or they can be due to bots and web scrapers which are part of common Internet background traffic.

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
* Network
* Threat Detection
* ML
* Command and Control

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Command and Control
    * ID: TA0011
    * Reference URL: [https://attack.mitre.org/tactics/TA0011/](https://attack.mitre.org/tactics/TA0011/)

* Technique:

    * Name: Application Layer Protocol
    * ID: T1071
    * Reference URL: [https://attack.mitre.org/techniques/T1071/](https://attack.mitre.org/techniques/T1071/)

* Sub-technique:

    * Name: Web Protocols
    * ID: T1071.001
    * Reference URL: [https://attack.mitre.org/techniques/T1071/001/](https://attack.mitre.org/techniques/T1071/001/)


