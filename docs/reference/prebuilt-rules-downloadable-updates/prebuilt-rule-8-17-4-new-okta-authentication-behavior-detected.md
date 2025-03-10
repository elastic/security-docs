---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-new-okta-authentication-behavior-detected.html
---

# New Okta Authentication Behavior Detected [prebuilt-rule-8-17-4-new-okta-authentication-behavior-detected]

Detects events where Okta behavior detection has identified a new authentication behavior.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

**Runs every**: 15m

**Searches indices from**: now-30m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection](https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection)
* [https://unit42.paloaltonetworks.com/muddled-libra/](https://unit42.paloaltonetworks.com/muddled-libra/)
* [https://help.okta.com/oie/en-us/content/topics/security/behavior-detection/about-behavior-detection.htm](https://help.okta.com/oie/en-us/content/topics/security/behavior-detection/about-behavior-detection.htm)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Use Case: Identity and Access Audit
* Tactic: Initial Access
* Data Source: Okta
* Resources: Investigation Guide

**Version**: 207

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_4274]

**Triage and analysis**

**Investigating New Okta Authentication Behavior Detected**

This rule detects events where Okta behavior detection has identified a new authentication behavior such as a new device or location.

**Possible investigation steps:**

* Identify the user involved in this action by examining the `okta.actor.id`, `okta.actor.type`, `okta.actor.alternate_id`, and `okta.actor.display_name` fields.
* Determine the authentication anomaly by examining the `okta.debug_context.debug_data.risk_behaviors` and `okta.debug_context.debug_data.flattened` fields.
* Determine the client used by the actor. Review the `okta.client.ip`, `okta.client.user_agent.raw_user_agent`, `okta.client.zone`, `okta.client.device`, and `okta.client.id` fields.
* If the client is a device, check the `okta.device.id`, `okta.device.name`, `okta.device.os_platform`, `okta.device.os_version`, and `okta.device.managed` fields.
* Review the past activities of the actor involved in this action by checking their previous actions.
* Examine the `okta.request.ip_chain` field to potentially determine if the actor used a proxy or VPN to perform this action.
* Evaluate the actions that happened just before and after this event in the `okta.event_type` field to help understand the full context of the activity.

**False positive analysis:**

* A user may be using a new device or location to sign in.
* The Okta behavior detection may be incorrectly identifying a new authentication behavior and need adjusted.

**Response and remediation:**

* If the user is legitimate and the authentication behavior is not suspicious, no action is required.
* If the user is legitimate but the authentication behavior is suspicious, consider resetting the user’s password and enabling multi-factor authentication (MFA).
* If MFA is already enabled, consider resetting MFA for the user.
* If the user is not legitimate, consider deactivating the user’s account.
* If this is a false positive, consider adjusting the Okta behavior detection settings.
* Block the IP address or device used in the attempts if they appear suspicious, using the data from the `okta.client.ip` and `okta.device.id` fields.
* Conduct a review of Okta policies and ensure they are in accordance with security best practices.


## Setup [_setup_1132]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5272]

```js
event.dataset:okta.system and okta.debug_context.debug_data.risk_behaviors:*
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Initial Access
    * ID: TA0001
    * Reference URL: [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)



