---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/attempt-to-revoke-okta-api-token.html
---

# Attempt to Revoke Okta API Token [attempt-to-revoke-okta-api-token]

Identifies attempts to revoke an Okta API token. An adversary may attempt to revoke or delete an Okta API token to disrupt an organization’s business operations.

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

**Version**: 411

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_165]

**Triage and analysis**

**Investigating Attempt to Revoke Okta API Token**

The rule alerts when attempts are made to revoke an Okta API token. The API tokens are critical for integration services, and revoking them may lead to disruption in services. Therefore, it’s important to validate these activities.

**Possible investigation steps:**

* Identify the actor associated with the API token revocation attempt. You can use the `okta.actor.alternate_id` field for this purpose.
* Determine the client used by the actor. Review the `okta.client.device`, `okta.client.ip`, `okta.client.user_agent.raw_user_agent`, `okta.client.ip_chain.ip`, and `okta.client.geographical_context` fields.
* Verify if the API token revocation was authorized or part of some planned activity.
* Check the `okta.outcome.result` and `okta.outcome.reason` fields to see if the attempt was successful or failed.
* Analyze the past activities of the actor involved in this action. An actor who usually performs such activities may indicate a legitimate reason.
* Evaluate the actions that happened just before and after this event. It can help understand the full context of the activity.

**False positive analysis:**

* It might be a false positive if the action was part of a planned activity or was performed by an authorized person.

**Response and remediation:**

* If unauthorized revocation attempts are confirmed, initiate the incident response process.
* Block the IP address or device used in the attempts, if they appear suspicious.
* Reset the user’s password and enforce MFA re-enrollment, if applicable.
* Conduct a review of Okta policies and ensure they are in accordance with security best practices.
* If the revoked token was used for critical integrations, coordinate with the relevant team to minimize the impact.


## Setup [_setup_103]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_169]

```js
event.dataset:okta.system and event.action:system.api_token.revoke
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Impact
    * ID: TA0040
    * Reference URL: [https://attack.mitre.org/tactics/TA0040/](https://attack.mitre.org/tactics/TA0040/)

* Technique:

    * Name: Account Access Removal
    * ID: T1531
    * Reference URL: [https://attack.mitre.org/techniques/T1531/](https://attack.mitre.org/techniques/T1531/)



