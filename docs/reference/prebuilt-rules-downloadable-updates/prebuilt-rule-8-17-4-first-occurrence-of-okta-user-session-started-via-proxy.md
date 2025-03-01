---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-first-occurrence-of-okta-user-session-started-via-proxy.html
---

# First Occurrence of Okta User Session Started via Proxy [prebuilt-rule-8-17-4-first-occurrence-of-okta-user-session-started-via-proxy]

Identifies the first occurrence of an Okta user session started via a proxy.

**Rule type**: new_terms

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://developer.okta.com/docs/reference/api/system-log/#issuer-object](https://developer.okta.com/docs/reference/api/system-log/#issuer-object)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection](https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Tactic: Initial Access
* Use Case: Identity and Access Audit
* Data Source: Okta
* Resources: Investigation Guide

**Version**: 206

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4273]

**Triage and analysis**

**Investigating First Occurrence of Okta User Session Started via Proxy**

This rule detects the first occurrence of an Okta user session started via a proxy. This rule is designed to help identify suspicious authentication behavior that may be indicative of an attacker attempting to gain access to an Okta account while remaining anonymous. This rule leverages the New Terms rule type feature where the `okta.actor.id` value is checked against the previous 7 days of data to determine if the value has been seen before for this activity.

**Possible investigation steps:**

* Identify the user involved in this action by examining the `okta.actor.id`, `okta.actor.type`, `okta.actor.alternate_id`, and `okta.actor.display_name` fields.
* Determine the client used by the actor. Review the `okta.client.ip`, `okta.client.user_agent.raw_user_agent`, `okta.client.zone`, `okta.client.device`, and `okta.client.id` fields.
* Examine the `okta.debug_context.debug_data.flattened` field for more information about the proxy used.
* Review the `okta.request.ip_chain` field for more information about the geographic location of the proxy.
* Review the past activities of the actor involved in this action by checking their previous actions.
* Evaluate the actions that happened just before and after this event in the `okta.event_type` field to help understand the full context of the activity.

**False positive analysis:**

* A user may have legitimately started a session via a proxy for security or privacy reasons.

**Response and remediation:**

* Review the profile of the user involved in this action to determine if proxy usage may be expected.
* If the user is legitimate and the authentication behavior is not suspicious, no action is required.
* If the user is legitimate but the authentication behavior is suspicious, consider resetting the user’s password and enabling multi-factor authentication (MFA).
* If MFA is already enabled, consider resetting MFA for the user.
* If the user is not legitimate, consider deactivating the user’s account.
* Conduct a review of Okta policies and ensure they are in accordance with security best practices.

**Setup**


## Setup [_setup_1131]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5271]

```js
event.dataset:okta.system and okta.event_type: (user.session.start or user.authentication.verify) and okta.security_context.is_proxy:true and not okta.actor.id: okta*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)

* Technique:

    * Name: External Remote Services
    * ID: T1133
    * Reference URL: [https://attack.mitre.org/techniques/T1133/](https://attack.mitre.org/techniques/T1133/)



