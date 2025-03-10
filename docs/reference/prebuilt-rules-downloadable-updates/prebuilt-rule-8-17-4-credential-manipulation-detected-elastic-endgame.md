---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-credential-manipulation-detected-elastic-endgame.html
---

# Credential Manipulation - Detected - Elastic Endgame [prebuilt-rule-8-17-4-credential-manipulation-detected-elastic-endgame]

Elastic Endgame detected Credential Manipulation. Click the Elastic Endgame icon in the event.module column or the link in the rule.reference column for additional information.

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
* Tactic: Privilege Escalation
* Resources: Investigation Guide

**Version**: 104

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4673]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Credential Manipulation - Detected - Elastic Endgame**

Elastic Endgame is a security solution that monitors and detects suspicious activities, such as credential manipulation, which adversaries exploit to escalate privileges by altering access tokens. This detection rule identifies such threats by analyzing alerts for token manipulation events, leveraging its high-risk score and severity to prioritize investigation. The rule aligns with MITRE ATT&CK’s framework, focusing on privilege escalation tactics.

**Possible investigation steps**

* Review the alert details to confirm the presence of event.kind:alert and event.module:endgame, ensuring the alert is relevant to Elastic Endgame’s detection capabilities.
* Examine the event.action and endgame.event_subtype_full fields for token_manipulation_event to understand the specific type of credential manipulation detected.
* Check the associated user account and system involved in the alert to determine if the activity aligns with expected behavior or if it indicates potential unauthorized access.
* Investigate the timeline of events leading up to and following the token manipulation event to identify any additional suspicious activities or patterns.
* Correlate the alert with other security events or logs to assess if this incident is part of a broader attack or isolated.
* Evaluate the risk score and severity to prioritize the response and determine if immediate action is required to mitigate potential threats.

**False positive analysis**

* Routine administrative tasks involving token manipulation can trigger alerts. Review the context of the event to determine if it aligns with expected administrative behavior.
* Automated scripts or software updates that require token changes might be flagged. Identify and whitelist these processes if they are verified as safe and necessary for operations.
* Security tools or monitoring solutions that interact with access tokens for legitimate purposes may cause false positives. Ensure these tools are recognized and excluded from triggering alerts.
* User behavior analytics might misinterpret legitimate user actions as suspicious. Regularly update user profiles and behavior baselines to minimize these occurrences.
* Scheduled maintenance activities that involve access token modifications should be documented and excluded from detection rules during their execution time.

**Response and remediation**

* Isolate the affected system immediately to prevent further unauthorized access or lateral movement within the network.
* Revoke and reset any compromised credentials or access tokens identified in the alert to prevent further misuse.
* Conduct a thorough review of recent access logs and token usage to identify any unauthorized access or actions taken by the adversary.
* Apply security patches and updates to the affected system and any related systems to close vulnerabilities that may have been exploited.
* Implement enhanced monitoring on the affected system and related accounts to detect any further suspicious activity or attempts at credential manipulation.
* Notify the security team and relevant stakeholders about the incident, providing details of the threat and actions taken, and escalate to higher management if the threat level increases.
* Review and update access control policies and token management practices to prevent similar incidents in the future, ensuring that least privilege principles are enforced.


## Setup [_setup_1488]

**Setup**

This rule is configured to generate more ***Max alerts per run*** than the default 1000 alerts per run set for all rules. This is to ensure that it captures as many alerts as possible.

***IMPORTANT:*** The rule’s ***Max alerts per run*** setting can be superseded by the `xpack.alerting.rules.run.alerts.max` Kibana config setting, which determines the maximum alerts generated by *any* rule in the Kibana alerting framework. For example, if `xpack.alerting.rules.run.alerts.max` is set to 1000, this rule will still generate no more than 1000 alerts even if its own ***Max alerts per run*** is set higher.

To make sure this rule can generate as many alerts as it’s configured in its own ***Max alerts per run*** setting, increase the `xpack.alerting.rules.run.alerts.max` system setting accordingly.

***NOTE:*** Changing `xpack.alerting.rules.run.alerts.max` is not possible in Serverless projects.


## Rule query [_rule_query_5628]

```js
event.kind:alert and event.module:endgame and endgame.metadata.type:detection and (event.action:token_manipulation_event or endgame.event_subtype_full:token_manipulation_event)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Privilege Escalation
    * ID: TA0004
    * Reference URL: [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)

* Technique:

    * Name: Access Token Manipulation
    * ID: T1134
    * Reference URL: [https://attack.mitre.org/techniques/T1134/](https://attack.mitre.org/techniques/T1134/)



