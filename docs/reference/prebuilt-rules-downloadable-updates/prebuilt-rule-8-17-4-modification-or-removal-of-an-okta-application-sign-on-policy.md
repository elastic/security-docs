---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-modification-or-removal-of-an-okta-application-sign-on-policy.html
---

# Modification or Removal of an Okta Application Sign-On Policy [prebuilt-rule-8-17-4-modification-or-removal-of-an-okta-application-sign-on-policy]

Detects attempts to modify or delete a sign on policy for an Okta application. An adversary may attempt to modify or delete the sign on policy for an Okta application in order to remove or weaken an organization’s security controls.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://help.okta.com/en/prod/Content/Topics/Security/App_Based_Signon.htm](https://help.okta.com/en/prod/Content/Topics/Security/App_Based_Signon.htm)
* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Tactic: Persistence
* Use Case: Identity and Access Audit
* Data Source: Okta
* Resources: Investigation Guide

**Version**: 411

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4289]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Modification or Removal of an Okta Application Sign-On Policy**

Okta’s sign-on policies are crucial for enforcing authentication controls within an organization. Adversaries may target these policies to weaken security by modifying or removing them, thus bypassing authentication measures. The detection rule monitors system events for updates or deletions of sign-on policies, flagging potential unauthorized changes to maintain security integrity.

**Possible investigation steps**

* Review the event logs for entries with the dataset field set to okta.system to confirm the source of the alert.
* Examine the event.action field for values application.policy.sign_on.update or application.policy.sign_on.rule.delete to identify the specific action taken.
* Identify the user or system account associated with the event to determine if the action was performed by an authorized individual.
* Check the timestamp of the event to correlate with any other suspicious activities or changes in the system around the same time.
* Investigate the history of changes to the affected sign-on policy to understand the context and frequency of modifications or deletions.
* Assess the impact of the policy change on the organization’s security posture and determine if any immediate remediation is necessary.
* If unauthorized activity is suspected, initiate a security incident response to contain and mitigate potential threats.

**False positive analysis**

* Routine administrative updates to sign-on policies by authorized personnel can trigger alerts. To manage this, establish a list of trusted users or roles and create exceptions for their actions.
* Scheduled maintenance or policy reviews may involve legitimate modifications or deletions. Document these activities and adjust the detection rule to exclude events during known maintenance windows.
* Automated scripts or tools used for policy management might cause false positives. Identify these tools and configure the rule to recognize and exclude their expected actions.
* Changes due to integration with third-party applications can be mistaken for unauthorized modifications. Verify these integrations and whitelist their associated actions to prevent unnecessary alerts.

**Response and remediation**

* Immediately isolate the affected Okta application to prevent further unauthorized access or changes. This can be done by disabling the application temporarily until the issue is resolved.
* Review the audit logs to identify the source of the modification or deletion attempt, focusing on the user account and IP address associated with the event.
* Revert any unauthorized changes to the sign-on policy by restoring it to the last known good configuration. Ensure that all security controls are reinstated.
* Conduct a thorough review of user accounts with administrative privileges in Okta to ensure they are legitimate and have not been compromised. Reset passwords and enforce multi-factor authentication (MFA) for these accounts.
* Notify the security team and relevant stakeholders about the incident, providing details of the attempted policy modification or deletion and the steps taken to contain the threat.
* Escalate the incident to higher-level security management if the source of the threat is internal or if there is evidence of a broader compromise.
* Implement additional monitoring and alerting for any future attempts to modify or delete sign-on policies, ensuring that similar threats are detected and addressed promptly.


## Setup [_setup_1146]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5287]

```js
event.dataset:okta.system and event.action:(application.policy.sign_on.update or application.policy.sign_on.rule.delete)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Persistence
    * ID: TA0003
    * Reference URL: [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)

* Technique:

    * Name: Modify Authentication Process
    * ID: T1556
    * Reference URL: [https://attack.mitre.org/techniques/T1556/](https://attack.mitre.org/techniques/T1556/)



