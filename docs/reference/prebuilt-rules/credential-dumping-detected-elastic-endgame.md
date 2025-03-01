---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/credential-dumping-detected-elastic-endgame.html
---

# Credential Dumping - Detected - Elastic Endgame [credential-dumping-detected-elastic-endgame]

Elastic Endgame detected Credential Dumping. Click the Elastic Endgame icon in the event.module column or the link in the rule.reference column for additional information.

**Rule type**: query

**Rule indices**:

* endgame-*

**Severity**: high

**Risk score**: 73

**Runs every**: 10m

**Searches indices from**: now-15m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 10000

**References**: None

**Tags**:

* Data Source: Elastic Endgame
* Use Case: Threat Detection
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_248]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Credential Dumping - Detected - Elastic Endgame**

Elastic Endgame is a security solution that monitors and detects suspicious activities, such as credential dumping, which is a technique used by adversaries to extract sensitive authentication data. Attackers exploit this to gain unauthorized access to systems. The detection rule identifies such threats by analyzing alerts and specific event actions related to credential theft, ensuring timely threat detection and response.

**Possible investigation steps**

* Review the alert details to confirm the presence of event.kind:alert and event.module:endgame, ensuring the alert is related to the Elastic Endgame detection.
* Examine the event.action and endgame.event_subtype_full fields for the value cred_theft_event to understand the specific credential theft activity detected.
* Check the associated host and user information to identify the potentially compromised system and user accounts.
* Investigate the timeline of events leading up to and following the alert to identify any suspicious activities or patterns that may indicate further compromise.
* Correlate the alert with other security events or logs to determine if this is part of a larger attack or isolated incident.
* Assess the risk score and severity to prioritize the response and determine if immediate action is required to contain the threat.
* Consult the MITRE ATT&CK framework for additional context on the T1003 technique to understand potential attacker methods and improve defensive measures.

**False positive analysis**

* Routine administrative tasks that involve legitimate credential access tools may trigger alerts. Users can create exceptions for known administrative accounts or tools that are frequently used in these tasks.
* Security software updates or scans that access credential stores might be flagged. Exclude these processes by identifying their specific event actions and adding them to the exception list.
* Automated scripts for system maintenance that require credential access could be misidentified. Review and whitelist these scripts by their unique identifiers or execution paths.
* Legitimate software installations that require elevated privileges may cause alerts. Monitor and exclude these installation processes by verifying their source and purpose.
* Regularly scheduled backups that access credential data might be detected. Ensure these backup processes are recognized and excluded by specifying their event actions in the rule configuration.

**Response and remediation**

* Isolate the affected system immediately to prevent further unauthorized access and lateral movement within the network.
* Terminate any suspicious processes identified as part of the credential dumping activity to halt ongoing malicious actions.
* Change all potentially compromised credentials, prioritizing those with elevated privileges, to mitigate unauthorized access risks.
* Conduct a thorough review of access logs and system events to identify any additional compromised accounts or systems.
* Restore affected systems from a known good backup to ensure the integrity of the system and data.
* Implement enhanced monitoring on the affected systems and accounts to detect any signs of recurring or related malicious activity.
* Escalate the incident to the security operations center (SOC) or incident response team for further investigation and to determine if additional containment or remediation actions are necessary.


## Setup [_setup_161]

**Setup**

This rule is configured to generate more ***Max alerts per run*** than the default 1000 alerts per run set for all rules. This is to ensure that it captures as many alerts as possible.

***IMPORTANT:*** The rule’s ***Max alerts per run*** setting can be superseded by the `xpack.alerting.rules.run.alerts.max` Kibana config setting, which determines the maximum alerts generated by *any* rule in the Kibana alerting framework. For example, if `xpack.alerting.rules.run.alerts.max` is set to 1000, this rule will still generate no more than 1000 alerts even if its own ***Max alerts per run*** is set higher.

To make sure this rule can generate as many alerts as it’s configured in its own ***Max alerts per run*** setting, increase the `xpack.alerting.rules.run.alerts.max` system setting accordingly.

***NOTE:*** Changing `xpack.alerting.rules.run.alerts.max` is not possible in Serverless projects.


## Rule query [_rule_query_259]

```js
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:cred_theft_event or endgame.event_subtype_full:cred_theft_event)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: OS Credential Dumping
    * ID: T1003
    * Reference URL: [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

* Sub-technique:

    * Name: LSASS Memory
    * ID: T1003.001
    * Reference URL: [https://attack.mitre.org/techniques/T1003/001/](https://attack.mitre.org/techniques/T1003/001/)



