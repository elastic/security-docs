---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-attempt-to-modify-an-okta-application.html
---

# Attempt to Modify an Okta Application [prebuilt-rule-8-17-4-attempt-to-modify-an-okta-application]

Detects attempts to modify an Okta application. An adversary may attempt to modify, deactivate, or delete an Okta application in order to weaken an organization’s security controls or disrupt their business operations.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://help.okta.com/en/prod/Content/Topics/Apps/Apps_Apps.htm](https://help.okta.com/en/prod/Content/Topics/Apps/Apps_Apps.htm)
* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Use Case: Identity and Access Audit
* Data Source: Okta
* Tactic: Impact
* Resources: Investigation Guide

**Version**: 410

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4271]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Attempt to Modify an Okta Application**

Okta is a widely used identity management service that helps organizations manage user access to applications securely. Adversaries may target Okta applications to alter, deactivate, or delete them, aiming to compromise security controls or disrupt operations. The detection rule monitors system events for application lifecycle updates, flagging unauthorized modification attempts to preempt potential security breaches.

**Possible investigation steps**

* Review the event logs for entries with event.dataset:okta.system and event.action:application.lifecycle.update to identify the specific application and user involved in the modification attempt.
* Verify the user’s role and permissions within Okta to determine if they have legitimate access to modify the application.
* Check for any recent changes in user permissions or roles that might explain the modification attempt.
* Investigate the history of the application in question to see if there have been any previous unauthorized modification attempts or related security incidents.
* Correlate the event timestamp with other security logs and alerts to identify any concurrent suspicious activities or patterns that might indicate a broader attack.

**False positive analysis**

* Routine administrative updates to Okta applications by authorized personnel can trigger alerts. To manage this, create exceptions for specific user accounts or roles known to perform regular maintenance.
* Scheduled application updates or maintenance activities may be flagged. Document these activities and adjust the monitoring schedule to avoid unnecessary alerts during these periods.
* Integration or testing environments often undergo frequent changes. Exclude these environments from monitoring or adjust the rule to focus on production environments only.
* Automated scripts or tools used for application management might generate false positives. Identify these tools and whitelist their actions to prevent unnecessary alerts.
* Changes made by third-party vendors or partners with legitimate access can be mistaken for unauthorized attempts. Ensure these entities are properly documented and their actions are accounted for in the monitoring setup.

**Response and remediation**

* Immediately isolate the affected Okta application to prevent further unauthorized modifications. This can be done by temporarily disabling the application or restricting access to it.
* Review and revoke any unauthorized changes made to the application settings. Restore the application to its last known good configuration using backup or audit logs.
* Conduct a thorough audit of recent access logs to identify any unauthorized users or suspicious activities related to the application lifecycle updates.
* Escalate the incident to the security operations team for further investigation and to determine if there are any broader security implications or related incidents.
* Implement additional monitoring on the affected application and similar applications to detect any further unauthorized modification attempts.
* Review and update access controls and permissions for Okta applications to ensure that only authorized personnel have the ability to modify application settings.
* Communicate with relevant stakeholders, including IT and security teams, to inform them of the incident and any changes made to the application settings as part of the remediation process.


## Setup [_setup_1129]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5269]

```js
event.dataset:okta.system and event.action:application.lifecycle.update
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)



