---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-2-1-unusual-web-user-agent.html
---

# Unusual Web User Agent [prebuilt-rule-8-2-1-unusual-web-user-agent]

A machine learning job detected a rare and unusual user agent indicating web browsing activity by an unusual process other than a web browser. This can be due to persistence, command-and-control, or exfiltration activity. Uncommon user agents coming from remote sources to local destinations are often the result of scanners, bots, and web scrapers, which are part of common Internet background traffic. Much of this is noise, but more targeted attacks on websites using tools like Burp or SQLmap can sometimes be discovered by spotting uncommon user agents. Uncommon user agents in traffic from local sources to remote destinations can be any number of things, including harmless programs like weather monitoring or stock-trading programs. However, uncommon user agents from local sources can also be due to malware or scanning activity.

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


