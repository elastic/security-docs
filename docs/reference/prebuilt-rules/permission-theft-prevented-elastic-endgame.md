---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/permission-theft-prevented-elastic-endgame.html
---

# Permission Theft - Prevented - Elastic Endgame [permission-theft-prevented-elastic-endgame]

Elastic Endgame prevented Permission Theft. Click the Elastic Endgame icon in the event.module column or the link in the rule.reference column for additional information.

**Rule type**: query

**Rule indices**:

* endgame-*

**Severity**: medium

**Risk score**: 47

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

## Investigation guide [_investigation_guide_616]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Permission Theft - Prevented - Elastic Endgame**

Elastic Endgame is a security solution that prevents unauthorized access by monitoring and blocking attempts to manipulate access tokens, a common privilege escalation tactic. Adversaries exploit token manipulation to gain elevated permissions without detection. The detection rule identifies and alerts on prevention events related to token protection, leveraging specific event types and actions to flag suspicious activities, thus mitigating potential threats.

**Possible investigation steps**

* Review the alert details to confirm the event.kind is *alert* and event.module is *endgame*, ensuring the alert is relevant to Elastic Endgame’s token protection.
* Examine the event.action and endgame.event_subtype_full fields to determine if the alert was triggered by a *token_protection_event*, which indicates an attempt to manipulate access tokens.
* Investigate the source and destination of the alert by analyzing associated IP addresses, user accounts, and hostnames to identify potential unauthorized access attempts.
* Check the endgame.metadata.type field to verify that the event type is *prevention*, confirming that the attempted permission theft was successfully blocked.
* Correlate the alert with other recent alerts or logs to identify patterns or repeated attempts that might indicate a persistent threat actor.
* Assess the risk score and severity level to prioritize the investigation and determine if immediate action is required to mitigate potential threats.

**False positive analysis**

* Routine administrative tasks involving legitimate token manipulation may trigger alerts. Review the context of the event to determine if it aligns with expected administrative activities.
* Scheduled scripts or automated processes that require token access might be flagged. Identify these processes and consider creating exceptions for known, safe operations.
* Software updates or installations that involve token changes can generate alerts. Verify the source and purpose of the update to ensure it is authorized, and exclude these events if they are part of regular maintenance.
* Security tools or monitoring solutions that interact with tokens for legitimate purposes may cause false positives. Cross-reference with known tool activities and whitelist these actions if they are verified as non-threatening.
* User behavior analytics might misinterpret legitimate user actions as suspicious. Analyze user activity patterns and adjust the detection thresholds or rules to better align with normal user behavior.

**Response and remediation**

* Immediately isolate the affected system to prevent further unauthorized access or privilege escalation attempts.
* Revoke any potentially compromised access tokens and force re-authentication for affected accounts to ensure that only legitimate users regain access.
* Conduct a thorough review of recent access logs and token usage to identify any unauthorized access or actions taken by the adversary.
* Apply patches or updates to the affected systems and applications to address any vulnerabilities that may have been exploited for token manipulation.
* Implement enhanced monitoring on the affected systems to detect any further attempts at access token manipulation or privilege escalation.
* Notify the security team and relevant stakeholders about the incident, providing details of the threat and actions taken, and escalate to higher management if the threat level increases.
* Review and update access control policies and token management practices to prevent similar incidents in the future, ensuring that only necessary permissions are granted and regularly audited.


## Setup [_setup_398]

**Setup**

This rule is configured to generate more ***Max alerts per run*** than the default 1000 alerts per run set for all rules. This is to ensure that it captures as many alerts as possible.

***IMPORTANT:*** The rule’s ***Max alerts per run*** setting can be superseded by the `xpack.alerting.rules.run.alerts.max` Kibana config setting, which determines the maximum alerts generated by *any* rule in the Kibana alerting framework. For example, if `xpack.alerting.rules.run.alerts.max` is set to 1000, this rule will still generate no more than 1000 alerts even if its own ***Max alerts per run*** is set higher.

To make sure this rule can generate as many alerts as it’s configured in its own ***Max alerts per run*** setting, increase the `xpack.alerting.rules.run.alerts.max` system setting accordingly.

***NOTE:*** Changing `xpack.alerting.rules.run.alerts.max` is not possible in Serverless projects.


## Rule query [_rule_query_658]

```js
event.kind:alert and event.module:endgame and endgame.metadata.type:prevention and (event.action:token_protection_event or endgame.event_subtype_full:token_protection_event)
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



