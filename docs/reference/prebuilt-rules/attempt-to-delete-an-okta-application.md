---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/attempt-to-delete-an-okta-application.html
---

# Attempt to Delete an Okta Application [attempt-to-delete-an-okta-application]

Detects attempts to delete an Okta application. An adversary may attempt to modify, deactivate, or delete an Okta application in order to weaken an organization’s security controls or disrupt their business operations.

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

## Investigation guide [_investigation_guide_147]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Attempt to Delete an Okta Application**

Okta is a widely used identity management service that helps organizations manage user access to applications securely. Adversaries may target Okta applications to disrupt operations or weaken security by attempting deletions. The detection rule monitors system events for deletion actions, flagging potential threats with a low-risk score, aiding analysts in identifying and mitigating unauthorized attempts.

**Possible investigation steps**

* Review the event logs for entries with event.dataset:okta.system and event.action:application.lifecycle.delete to confirm the attempted deletion action.
* Identify the user account associated with the deletion attempt and verify their role and permissions within the organization to assess if the action was authorized.
* Check the timestamp of the event to determine if the deletion attempt coincides with any known maintenance windows or authorized changes.
* Investigate the specific Okta application targeted for deletion to understand its importance and potential impact on business operations if it were successfully deleted.
* Examine any recent changes or unusual activities associated with the user account or the targeted application to identify potential indicators of compromise.
* Correlate this event with other security alerts or logs to determine if it is part of a broader attack or isolated incident.

**False positive analysis**

* Routine maintenance activities by IT staff may trigger the rule when they legitimately delete or modify applications. To manage this, create exceptions for known maintenance periods or specific user accounts responsible for these tasks.
* Automated scripts or tools used for application lifecycle management might generate false positives. Identify these scripts and exclude their actions from triggering alerts by whitelisting their associated user accounts or service accounts.
* Testing environments where applications are frequently created and deleted for development purposes can lead to false positives. Exclude these environments from monitoring or adjust the rule to ignore actions within specific test domains.
* Changes in application configurations by authorized personnel for legitimate business needs may be flagged. Implement a process to log and approve such changes, allowing for easy identification and exclusion from alerts.

**Response and remediation**

* Immediately isolate the affected Okta application to prevent further unauthorized actions. This can be done by temporarily disabling the application or restricting access to it.
* Review the audit logs and event details associated with the deletion attempt to identify the source of the action, including user accounts and IP addresses involved.
* Revoke access for any compromised or suspicious user accounts identified in the investigation to prevent further unauthorized actions.
* Restore the deleted application from backup if applicable, ensuring that all configurations and settings are intact.
* Notify the security team and relevant stakeholders about the incident, providing details of the attempted deletion and actions taken.
* Conduct a root cause analysis to determine how the unauthorized attempt was made and implement additional security controls to prevent similar incidents in the future.
* Enhance monitoring and alerting for Okta application lifecycle events to ensure rapid detection and response to any future unauthorized modification or deletion attempts.


## Setup [_setup_87]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_151]

```js
event.dataset:okta.system and event.action:application.lifecycle.delete
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Service Stop
    * ID: T1489
    * Reference URL: [https://attack.mitre.org/techniques/T1489/](https://attack.mitre.org/techniques/T1489/)



