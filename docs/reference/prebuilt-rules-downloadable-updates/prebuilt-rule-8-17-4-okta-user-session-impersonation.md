---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-okta-user-session-impersonation.html
---

# Okta User Session Impersonation [prebuilt-rule-8-17-4-okta-user-session-impersonation]

A user has initiated a session impersonation granting them access to the environment with the permissions of the user they are impersonating. This would likely indicate Okta administrative access and should only ever occur if requested and expected.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: high

**Risk score**: 73

**Runs every**: 15m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://blog.cloudflare.com/cloudflare-investigation-of-the-january-2022-okta-compromise/](https://blog.cloudflare.com/cloudflare-investigation-of-the-january-2022-okta-compromise/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)
* [https://www.elastic.co/security-labs/okta-and-lapsus-what-you-need-to-know](https://www.elastic.co/security-labs/okta-and-lapsus-what-you-need-to-know)

**Tags**:

* Use Case: Identity and Access Audit
* Tactic: Credential Access
* Data Source: Okta
* Resources: Investigation Guide

**Version**: 412

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4256]

**Triage and analysis**

**Investigating Okta User Session Impersonation**

The detection of an Okta User Session Impersonation indicates that a user has initiated a session impersonation which grants them access with the permissions of the user they are impersonating. This type of activity typically indicates Okta administrative access and should only ever occur if requested and expected.

**Possible investigation steps**

* Identify the actor associated with the impersonation event by checking the `okta.actor.id`, `okta.actor.type`, `okta.actor.alternate_id`, or `okta.actor.display_name` fields.
* Review the `event.action` field to confirm the initiation of the impersonation event.
* Check the `event.time` field to understand the timing of the event.
* Check the `okta.target.id`, `okta.target.type`, `okta.target.alternate_id`, or `okta.target.display_name` to identify the user who was impersonated.
* Review any activities that occurred during the impersonation session. Look for any activities related to the impersonated user’s account during and after the impersonation event.

**False positive analysis**

* Verify if the session impersonation was part of an approved activity. Check if it was associated with any documented administrative tasks or troubleshooting efforts.
* Ensure that the impersonation session was initiated by an authorized individual. You can check this by verifying the `okta.actor.id` or `okta.actor.display_name` against the list of approved administrators.

**Response and remediation**

* If the impersonation was not authorized, consider it as a breach. Suspend the user account of the impersonator immediately.
* Reset the user session and invalidate any active sessions related to the impersonated user.
* If a specific impersonation technique was used, ensure that systems are patched or configured to prevent such techniques.
* Conduct a thorough investigation to understand the extent of the breach and the potential impact on the systems and data.
* Review and update your security policies to prevent such incidents in the future.
* Implement additional monitoring and logging of Okta events to improve visibility of user actions.


## Setup [_setup_1115]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5254]

```js
event.dataset:okta.system and event.action:user.session.impersonation.initiate
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)



