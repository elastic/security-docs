---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/my-first-rule.html
---

# My First Rule [my-first-rule]

This rule helps you test and practice using alerts with Elastic Security as you get set up. It’s not a sign of threat activity.

**Rule type**: threshold

**Rule indices**:

* auditbeat-*
* filebeat-*
* logs-*
* winlogbeat-*

**Severity**: low

**Risk score**: 21

**Runs every**: 30m

**Searches indices from**: now-35m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 1

**References**:

* [/reference/security/prebuilt-rules/index.md](/reference/prebuilt-rules/index.md)

**Tags**:

* Use Case: Guided Onboarding
* Resources: Investigation Guide

**Version**: 5

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_565]

**Triage and analysis**

[TBC: QUOTE]
**Investigating My First Rule**

Elastic Security leverages event data to monitor and alert on potential security incidents. The "My First Rule" is a foundational rule designed for onboarding, focusing on event data without indicating a specific threat. Adversaries might exploit event logging to obscure their tracks or trigger false alerts. This rule helps analysts familiarize themselves with event-based alerts, ensuring they can identify and respond to genuine threats effectively.

**Possible investigation steps**

* Review the event data associated with the alert to understand the context and source of the event.kind:event.
* Check the timestamp of the event to determine when the activity occurred and correlate it with other events around the same time.
* Identify the host or user associated with the event to assess if there is any unusual or unauthorized activity.
* Examine related logs or events from the same source to identify any patterns or anomalies that could indicate suspicious behavior.
* Consult with team members or use internal resources to determine if the event is part of normal operations or if it requires further investigation.

**False positive analysis**

* Routine system events can trigger alerts, as the rule monitors all event data without filtering for specific threats.
* Identify and document common non-threatening events that frequently trigger alerts, such as regular system updates or scheduled tasks.
* Use exceptions to exclude these documented non-threatening events from triggering alerts, reducing noise and focusing on genuine threats.
* Regularly review and update the list of exceptions to ensure it remains relevant and does not inadvertently exclude new potential threats.
* Collaborate with IT and operations teams to understand normal event patterns and adjust the rule’s exceptions accordingly.

**Response and remediation**

* Verify the legitimacy of the event by cross-referencing with known benign activities or scheduled tasks to rule out false positives.
* Contain any potential threat by isolating affected systems or accounts if suspicious activity is confirmed, preventing further unauthorized access or damage.
* Remediate by reviewing and adjusting logging configurations to ensure accurate event capture and reduce the risk of adversaries exploiting logging mechanisms.
* Escalate the incident to the appropriate security team or management if the event correlates with other suspicious activities or if it indicates a potential breach.
* Enhance detection capabilities by updating alerting rules to include additional context or indicators observed during the investigation, ensuring better identification of similar threats in the future.

This is a test alert.

This alert does not show threat activity. Elastic created this alert to help you understand how alerts work.

For normal rules, the Investigation Guide will help analysts investigate alerts.

This alert will show once every 24 hours for each host. It is safe to disable this rule.


## Rule query [_rule_query_606]

```js
event.kind:event
```


