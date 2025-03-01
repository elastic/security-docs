---
applies_to:
  stack: all
  serverless:
    security: all
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/attempt-to-modify-an-okta-policy.html
---

# Attempt to Modify an Okta Policy [attempt-to-modify-an-okta-policy]

Detects attempts to modify an Okta policy. An adversary may attempt to modify an Okta policy in order to weaken an organization’s security controls. For example, an adversary may attempt to modify an Okta multi-factor authentication (MFA) policy in order to weaken the authentication requirements for user accounts.

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
* Tactic: Defense Evasion
* Resources: Investigation Guide

**Version**: 411

**Rule authors**:

* Elastic

**Rule license**: Elastic License v2

## Investigation guide [_investigation_guide_161]

**Triage and analysis**

**Investigating Attempt to Modify an Okta Policy**

Modifications to Okta policies may indicate attempts to weaken an organization’s security controls. If such an attempt is detected, consider the following steps for investigation.

**Possible investigation steps:**

* Identify the actor associated with the event. Check the fields `okta.actor.id`, `okta.actor.type`, `okta.actor.alternate_id`, and `okta.actor.display_name`.
* Determine the client used by the actor. You can look at `okta.client.device`, `okta.client.ip`, `okta.client.user_agent.raw_user_agent`, `okta.client.ip_chain.ip`, and `okta.client.geographical_context`.
* Check the nature of the policy modification. You can review the `okta.target` field, especially `okta.target.display_name` and `okta.target.id`.
* Examine the `okta.outcome.result` and `okta.outcome.reason` fields to understand the outcome of the modification attempt.
* Check if there have been other similar modification attempts in a short time span from the same actor or IP address.

**False positive analysis:**

* This alert might be a false positive if Okta policies are regularly updated in your organization as a part of normal operations.
* Check if the actor associated with the event has legitimate rights to modify the Okta policies.
* Verify the actor’s geographical location and the time of the modification attempt. If these align with the actor’s regular behavior, it could be a false positive.

**Response and remediation:**

* If unauthorized modification is confirmed, initiate the incident response process.
* Lock the actor’s account and enforce password change as an immediate response.
* Reset MFA tokens for the actor and enforce re-enrollment, if applicable.
* Review any other actions taken by the actor to assess the overall impact.
* If the attack was facilitated by a particular technique, ensure your systems are patched or configured to prevent such techniques.
* Consider a security review of your Okta policies and rules to ensure they follow security best practices.


## Setup [_setup_99]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_165]

```js
event.dataset:okta.system and event.action:policy.lifecycle.update
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



