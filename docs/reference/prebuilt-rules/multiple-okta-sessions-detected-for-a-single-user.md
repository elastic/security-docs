---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/multiple-okta-sessions-detected-for-a-single-user.html
---

# Multiple Okta Sessions Detected for a Single User [multiple-okta-sessions-detected-for-a-single-user]

Detects when a user has started multiple Okta sessions with the same user account and different session IDs. This may indicate that an attacker has stolen the user’s session cookie and is using it to access the user’s account from a different location.

**Rule type**: threshold

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

**Runs every**: 30m

**Searches indices from**: now-35m ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection](https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Use Case: Identity and Access Audit
* Data Source: Okta
* Tactic: Lateral Movement
* Resources: Investigation Guide

**Version**: 208

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_560]

**Triage and analysis**

[TBC: QUOTE]
**Investigating Multiple Okta Sessions Detected for a Single User**

Okta is a widely used identity management service that facilitates secure user authentication and access control. Adversaries may exploit Okta by hijacking session cookies, allowing unauthorized access to user accounts from different locations. The detection rule identifies anomalies by flagging multiple session initiations with distinct session IDs for the same user, excluding legitimate Okta system actors, thus highlighting potential unauthorized access attempts.

**Possible investigation steps**

* Review the Okta logs to identify the specific user account associated with the multiple session initiations and note the distinct session IDs.
* Check the geographic locations and IP addresses associated with each session initiation to determine if there are any unusual or unexpected locations.
* Investigate the timestamps of the session initiations to see if they align with the user’s typical login patterns or if they suggest simultaneous logins from different locations.
* Examine the okta.actor.id and okta.actor.display_name fields to ensure that the sessions were not initiated by legitimate Okta system actors.
* Contact the user to verify if they recognize the session activity and if they have recently logged in from multiple devices or locations.
* Assess if there are any other related security alerts or incidents involving the same user account that could indicate a broader compromise.

**False positive analysis**

* Legitimate multiple device usage: Users may legitimately access their accounts from multiple devices, leading to multiple session initiations. To handle this, create exceptions for users who frequently use multiple devices for work.
* Frequent travel or remote work: Users who travel often or work remotely may trigger this rule due to accessing Okta from various locations. Consider setting up location-based exceptions for these users.
* Shared accounts: In environments where account sharing is common, multiple sessions may be expected. Implement policies to discourage account sharing or create exceptions for known shared accounts.
* Automated scripts or integrations: Some users may have automated processes that initiate multiple sessions. Identify these scripts and exclude them from the rule by their specific session patterns.
* Testing and development environments: Users involved in testing or development may generate multiple sessions as part of their work. Exclude these environments from the rule to prevent false positives.

**Response and remediation**

* Immediately terminate all active sessions for the affected user account to prevent further unauthorized access.
* Reset the user’s password and invalidate any existing session cookies to ensure that any stolen session cookies are rendered useless.
* Conduct a thorough review of recent login activity and session logs for the affected user to identify any suspicious or unauthorized access patterns.
* Notify the user of the potential compromise and advise them to verify any recent account activity for unauthorized actions.
* Escalate the incident to the security operations team for further investigation and to determine if additional accounts or systems may be affected.
* Implement multi-factor authentication (MFA) for the affected user account if not already in place, to add an additional layer of security against unauthorized access.
* Update and enhance monitoring rules to detect similar anomalies in the future, focusing on unusual session patterns and access from unexpected locations.


## Setup [_setup_363]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_601]

```js
event.dataset:okta.system
    and okta.event_type:user.session.start
    and okta.authentication_context.external_session_id:*
    and not (okta.actor.id: okta* or okta.actor.display_name: okta*)
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Lateral Movement
    * ID: TA0008
    * Reference URL: [https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/)

* Technique:

    * Name: Use Alternate Authentication Material
    * ID: T1550
    * Reference URL: [https://attack.mitre.org/techniques/T1550/](https://attack.mitre.org/techniques/T1550/)

* Sub-technique:

    * Name: Web Session Cookie
    * ID: T1550.004
    * Reference URL: [https://attack.mitre.org/techniques/T1550/004/](https://attack.mitre.org/techniques/T1550/004/)



