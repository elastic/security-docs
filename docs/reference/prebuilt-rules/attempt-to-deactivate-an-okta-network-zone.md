---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/attempt-to-deactivate-an-okta-network-zone.html
---

# Attempt to Deactivate an Okta Network Zone [attempt-to-deactivate-an-okta-network-zone]

Detects attempts to deactivate an Okta network zone. Okta network zones can be configured to limit or restrict access to a network based on IP addresses or geolocations. An adversary may attempt to modify, delete, or deactivate an Okta network zone in order to remove or weaken an organization’s security controls.

**Rule type**: query

**Rule indices**:

* filebeat-*
* logs-okta*

**Severity**: medium

**Risk score**: 47

**Runs every**: 5m

**Searches indices from**: None ({{ref}}/common-options.html#date-math[Date Math format], see also [`Additional look-back time`](docs-content://solutions/security/detect-and-alert/create-detection-rule.md#rule-schedule))

**Maximum alerts per execution**: 100

**References**:

* [https://help.okta.com/en/prod/Content/Topics/Security/network/network-zones.htm](https://help.okta.com/en/prod/Content/Topics/Security/network/network-zones.htm)
* [https://developer.okta.com/docs/reference/api/system-log/](https://developer.okta.com/docs/reference/api/system-log/)
* [https://developer.okta.com/docs/reference/api/event-types/](https://developer.okta.com/docs/reference/api/event-types/)
* [https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy](https://www.elastic.co/security-labs/testing-okta-visibility-and-detection-dorothy)
* [https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security](https://www.elastic.co/security-labs/monitoring-okta-threats-with-elastic-security)
* [https://www.elastic.co/security-labs/starter-guide-to-understanding-okta](https://www.elastic.co/security-labs/starter-guide-to-understanding-okta)

**Tags**:

* Use Case: Identity and Access Audit
* Data Source: Okta
* Use Case: Network Security Monitoring
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 411

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_144]

**Triage and analysis**

**Investigating Attempt to Deactivate an Okta Network Zone**

The Okta network zones can be configured to restrict or limit access to a network based on IP addresses or geolocations. Deactivating a network zone in Okta may remove or weaken the security controls of an organization, which might be an indicator of an adversary’s attempt to evade defenses.

**Possible investigation steps**

* Identify the actor related to the alert by reviewing the `okta.actor.id`, `okta.actor.type`, `okta.actor.alternate_id`, or `okta.actor.display_name` fields.
* Examine the `event.action` field to confirm the deactivation of a network zone.
* Check the `okta.target.id`, `okta.target.type`, `okta.target.alternate_id`, or `okta.target.display_name` to identify the network zone that was deactivated.
* Investigate the `event.time` field to understand when the event happened.
* Review the actor’s activities before and after the event to understand the context of this event.

**False positive analysis**

* Check the `okta.client.user_agent.raw_user_agent` field to understand the device and software used by the actor. If these match the actor’s normal behavior, it might be a false positive.
* Check if the actor is a known administrator or part of the IT team who might have a legitimate reason to deactivate a network zone.
* Verify the actor’s actions with any known planned changes or maintenance activities.

**Response and remediation**

* If unauthorized access or actions are confirmed, immediately lock the affected actor account and require a password change.
* Re-enable the deactivated network zone if it was deactivated without authorization.
* Review and update the privileges of the actor who initiated the deactivation.
* Check the security policies and procedures to identify any gaps and update them as necessary.
* Implement additional monitoring and logging of Okta events to improve visibility of user actions.
* Communicate and train the employees about the importance of following proper procedures for modifying network zone settings.


## Setup [_setup_84]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_148]

```js
event.dataset:okta.system and event.action:zone.deactivate
```

**Framework**: MITRE ATT&CKTM

* Tactic:

    * Name: Defense Evasion
    * ID: TA0005
    * Reference URL: [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)

* Technique:

    * Name: Impair Defenses
    * ID: T1562
    * Reference URL: [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

* Sub-technique:

    * Name: Disable or Modify Cloud Firewall
    * ID: T1562.007
    * Reference URL: [https://attack.mitre.org/techniques/T1562/007/](https://attack.mitre.org/techniques/T1562/007/)



