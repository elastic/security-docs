---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/attempt-to-deactivate-an-okta-application.html
---

# Attempt to Deactivate an Okta Application [attempt-to-deactivate-an-okta-application]

Detects attempts to deactivate an Okta application. An adversary may attempt to modify, deactivate, or delete an Okta application in order to weaken an organization’s security controls or disrupt their business operations.

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

**Version**: 411

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_143]

**Triage and analysis**

**Investigating Attempt to Deactivate an Okta Application**

This rule detects attempts to deactivate an Okta application. Unauthorized deactivation could lead to disruption of services and pose a significant risk to the organization.

**Possible investigation steps:**

* Identify the actor associated with the deactivation attempt by examining the `okta.actor.id`, `okta.actor.type`, `okta.actor.alternate_id`, and `okta.actor.display_name` fields.
* Determine the client used by the actor. Review the `okta.client.ip`, `okta.client.user_agent.raw_user_agent`, `okta.client.zone`, `okta.client.device`, and `okta.client.id` fields.
* If the client is a device, check the `okta.device.id`, `okta.device.name`, `okta.device.os_platform`, `okta.device.os_version`, and `okta.device.managed` fields.
* Understand the context of the event from the `okta.debug_context.debug_data` and `okta.authentication_context` fields.
* Check the `okta.outcome.result` and `okta.outcome.reason` fields to see if the attempt was successful or failed.
* Review the past activities of the actor involved in this action by checking their previous actions logged in the `okta.target` field.
* Analyze the `okta.transaction.id` and `okta.transaction.type` fields to understand the context of the transaction.
* Evaluate the actions that happened just before and after this event in the `okta.event_type` field to help understand the full context of the activity.

**False positive analysis:**

* It might be a false positive if the action was part of a planned activity, performed by an authorized person, or if the `okta.outcome.result` field shows a failure.
* An unsuccessful attempt might also indicate an authorized user having trouble rather than a malicious activity.

**Response and remediation:**

* If unauthorized deactivation attempts are confirmed, initiate the incident response process.
* Block the IP address or device used in the attempts if they appear suspicious, using the data from the `okta.client.ip` and `okta.device.id` fields.
* Reset the user’s password and enforce MFA re-enrollment, if applicable.
* Conduct a review of Okta policies and ensure they are in accordance with security best practices.
* If the deactivated application was crucial for business operations, coordinate with the relevant team to reactivate it and minimize the impact.


## Setup [_setup_83]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_147]

```js
event.dataset:okta.system and event.action:application.lifecycle.deactivate
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



