---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/multiple-okta-user-authentication-events-with-same-device-token-hash.html
---

# Multiple Okta User Authentication Events with Same Device Token Hash [multiple-okta-user-authentication-events-with-same-device-token-hash]

Detects when a high number of Okta user authentication events are reported for multiple users in a short time frame. Adversaries may attempt to launch a credential stuffing or password spraying attack from the same device by using a list of known usernames and passwords to gain unauthorized access to user accounts.

**Rule type**: esql

**Rule indices**: None

**Severity**: low

**Risk score**: 21

**Runs every**: 5m

**Searches indices from**: now-9m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://support.okta.com/help/s/article/How-does-the-Device-Token-work?language=en_US](https://support.okta.com/help/s/article/How-does-the-Device-Token-work?language=en_US)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection](https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection)
* [https://www.okta.com/resources/whitepaper-how-adaptive-mfa-can-help-in-mitigating-brute-force-attacks/](https://www.okta.com/resources/whitepaper-how-adaptive-mfa-can-help-in-mitigating-brute-force-attacks/)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Use Case: Identity and Access Audit
* Data Source: Okta
* Tactic: Credential Access
* Resources: Investigation Guide

**Version**: 204

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_563]

**Triage and analysis**

**Investigating Multiple Okta User Authentication Events with Same Device Token Hash**

This rule detects when a high number of Okta user authentication events are reported for multiple users in a short time frame. Adversaries may attempt to launch a credential stuffing attack from the same device by using a list of known usernames and passwords to gain unauthorized access to user accounts. Note that Okta does not log unrecognized usernames supplied during authentication attempts, so this rule may not detect all credential stuffing attempts or may indicate a targeted attack.

**Possible investigation steps:**

* Since this is an ES|QL rule, the `okta.actor.alternate_id` and `okta.debug_context.debug_data.dt_hash` values can be used to pivot into the raw authentication events related to this activity.
* Identify the users involved in this action by examining the `okta.actor.id`, `okta.actor.type`, `okta.actor.alternate_id`, and `okta.actor.display_name` fields.
* Determine the device client used for these actions by analyzing `okta.client.ip`, `okta.client.user_agent.raw_user_agent`, `okta.client.zone`, `okta.client.device`, and `okta.client.id` fields.
* Review the `okta.security_context.is_proxy` field to determine if the device is a proxy.
* If the device is a proxy, this may indicate that a user is using a proxy to access multiple accounts for password spraying.
* With the list of `okta.actor.alternate_id` values, review `event.outcome` results to determine if the authentication was successful.
* If the authentication was successful for any user, pivoting to `event.action` values for those users may provide additional context.
* With Okta end users identified, review the `okta.debug_context.debug_data.dt_hash` field.
* Historical analysis should indicate if this device token hash is commonly associated with the user.
* Review the `okta.event_type` field to determine the type of authentication event that occurred.
* If the event type is `user.authentication.sso`, the user may have legitimately started a session via a proxy for security or privacy reasons.
* If the event type is `user.authentication.password`, the user may be using a proxy to access multiple accounts for password spraying.
* Examine the `okta.outcome.result` field to determine if the authentication was successful.
* Review the past activities of the actor(s) involved in this action by checking their previous actions.
* Evaluate the actions that happened just before and after this event in the `okta.event_type` field to help understand the full context of the activity.
* This may help determine the authentication and authorization actions that occurred between the user, Okta and application.

**False positive analysis:**

* A user may have legitimately started a session via a proxy for security or privacy reasons.
* Users may share an endpoint related to work or personal use in which separate Okta accounts are used.
* Architecturally, this shared endpoint may leverage a proxy for security or privacy reasons.
* Shared systems such as Kiosks and conference room computers may be used by multiple users.
* Shared working spaces may have a single endpoint that is used by multiple users.

**Response and remediation:**

* Review the profile of the users involved in this action to determine if proxy usage may be expected.
* If the user is legitimate and the authentication behavior is not suspicious based on device analysis, no action is required.
* If the user is legitimate but the authentication behavior is suspicious, consider resetting passwords for the users involves and enabling multi-factor authentication (MFA).
* If MFA is already enabled, consider resetting MFA for the users.
* If any of the users are not legitimate, consider deactivating the user’s account.
* Conduct a review of Okta policies and ensure they are in accordance with security best practices.
* Check with internal IT teams to determine if the accounts involved recently had MFA reset at the request of the user.
* If so, confirm with the user this was a legitimate request.
* If so and this was not a legitimate request, consider deactivating the user’s account temporarily.
* Reset passwords and reset MFA for the user.
* If this is a false positive, consider adding the `okta.debug_context.debug_data.dt_hash` field to the `exceptions` list in the rule.
* This will prevent future occurrences of this event for this device from triggering the rule.


## Setup [_setup_366]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_604]

```js
FROM logs-okta*
| WHERE
    event.dataset == "okta.system"
    AND (event.action RLIKE "user\\.authentication(.*)" OR event.action == "user.session.start")
    AND okta.debug_context.debug_data.dt_hash != "-"
    AND okta.outcome.reason == "INVALID_CREDENTIALS"
| KEEP event.action, okta.debug_context.debug_data.dt_hash, okta.actor.id, okta.actor.alternate_id, okta.outcome.reason
| STATS
    target_auth_count = COUNT_DISTINCT(okta.actor.id)
    BY okta.debug_context.debug_data.dt_hash, okta.actor.alternate_id
| WHERE
    target_auth_count > 20
| SORT
    target_auth_count DESC
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Credential Access
    * ID: TA0006
    * Reference URL: [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)

* Technique:

    * Name: Brute Force
    * ID: T1110
    * Reference URL: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)

* Sub-technique:

    * Name: Password Spraying
    * ID: T1110.003
    * Reference URL: [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)

* Technique:

    * Name: Brute Force
    * ID: T1110
    * Reference URL: [https://attack.mitre.org/techniques/T1110/](https://attack.mitre.org/techniques/T1110/)

* Sub-technique:

    * Name: Credential Stuffing
    * ID: T1110.004
    * Reference URL: [https://attack.mitre.org/techniques/T1110/004/](https://attack.mitre.org/techniques/T1110/004/)



