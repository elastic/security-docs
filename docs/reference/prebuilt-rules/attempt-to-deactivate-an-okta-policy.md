---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/attempt-to-deactivate-an-okta-policy.html
---

# Attempt to Deactivate an Okta Policy [attempt-to-deactivate-an-okta-policy]

Detects attempts to deactivate an Okta policy. An adversary may attempt to deactivate an Okta policy in order to weaken an organization’s security controls. For example, an adversary may attempt to deactivate an Okta multi-factor authentication (MFA) policy in order to weaken the authentication requirements for user accounts.

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

* [https://help.okta.com/en/prod/Content/Topics/Security/Security_Policies.htm](https://help.okta.com/en/prod/Content/Topics/Security/Security_Policies.htm)
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

## Investigation guide [_investigation_guide_145]

**Triage and analysis**

**Investigating Attempt to Deactivate an Okta Policy**

Okta policies define rules to manage user access to resources. Policies such as multi-factor authentication (MFA) are critical for enforcing strong security measures. Deactivation of an Okta policy could potentially weaken the security posture, allowing for unauthorized access or facilitating other malicious activities.

This rule is designed to detect attempts to deactivate an Okta policy, which could be indicative of an adversary’s attempt to weaken an organization’s security controls. For example, disabling an MFA policy could lower the security of user authentication processes.

**Possible investigation steps:**

* Identify the actor related to the alert by reviewing `okta.actor.id`, `okta.actor.type`, `okta.actor.alternate_id`, or `okta.actor.display_name` fields in the alert.
* Review the `okta.client.user_agent.raw_user_agent` field to understand the device and software used by the actor.
* Examine the `okta.outcome.reason` field for additional context around the deactivation attempt.
* Check the `okta.outcome.result` field to confirm the policy deactivation attempt.
* Check if there are multiple policy deactivation attempts from the same actor or IP address (`okta.client.ip`).
* Check for successful logins immediately following the policy deactivation attempt.
* Verify whether the actor’s activity aligns with typical behavior or if any unusual activity took place around the time of the deactivation attempt.

**False positive analysis:**

* Check if there were issues with the Okta system at the time of the deactivation attempt. This could indicate a system error rather than a genuine threat activity.
* Check the geographical location (`okta.request.ip_chain.geographical_context`) and time of the deactivation attempt. If these match the actor’s normal behavior, it might be a false positive.
* Verify the actor’s administrative rights to ensure they are correctly configured.

**Response and remediation:**

* If unauthorized policy deactivation is confirmed, initiate the incident response process.
* Immediately lock the affected actor account and require a password change.
* Consider resetting MFA tokens for the actor and require re-enrollment.
* Check if the compromised account was used to access or alter any sensitive data or systems.
* If a specific deactivation technique was used, ensure your systems are patched or configured to prevent such techniques.
* Assess the criticality of affected services and servers.
* Work with your IT team to minimize the impact on users and maintain business continuity.
* If multiple accounts are affected, consider a broader reset or audit of MFA tokens.
* Implement security best practices [outlined](https://www.okta.com/blog/2019/10/9-admin-best-practices-to-keep-your-org-secure/) by Okta.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_85]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_149]

```js
event.dataset:okta.system and event.action:policy.lifecycle.deactivate
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



