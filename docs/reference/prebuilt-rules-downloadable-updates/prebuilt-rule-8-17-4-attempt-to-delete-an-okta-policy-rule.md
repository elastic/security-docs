---
mapped_pages:
  - https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-17-4-attempt-to-delete-an-okta-policy-rule.html
---

# Attempt to Delete an Okta Policy Rule [prebuilt-rule-8-17-4-attempt-to-delete-an-okta-policy-rule]

Detects attempts to delete a rule within an Okta policy. An adversary may attempt to delete an Okta policy rule in order to weaken an organization’s security controls.

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

## Investigation guide [_investigation_guide_4263]

**Triage and analysis**

**Investigating Attempt to Delete an Okta Policy Rule**

Okta policy rules are integral components of an organization’s security controls, as they define how user access to resources is managed. Deletion of a rule within an Okta policy could potentially weaken the organization’s security posture, allowing for unauthorized access or facilitating other malicious activities.

This rule detects attempts to delete an Okta policy rule, which could indicate an adversary’s attempt to weaken an organization’s security controls. Adversaries may do this to circumvent security measures and enable further malicious activities.

**Possible investigation steps:**

* Identify the actor related to the alert by reviewing `okta.actor.id`, `okta.actor.type`, `okta.actor.alternate_id`, or `okta.actor.display_name` fields in the alert.
* Review the `okta.client.user_agent.raw_user_agent` field to understand the device and software used by the actor.
* Examine the `okta.outcome.reason` field for additional context around the deletion attempt.
* Check the `okta.outcome.result` field to confirm the policy rule deletion attempt.
* Check if there are multiple policy rule deletion attempts from the same actor or IP address (`okta.client.ip`).
* Check for successful logins immediately following the policy rule deletion attempt.
* Verify whether the actor’s activity aligns with typical behavior or if any unusual activity took place around the time of the deletion attempt.

**False positive analysis:**

* Check if there were issues with the Okta system at the time of the deletion attempt. This could indicate a system error rather than a genuine threat activity.
* Check the geographical location (`okta.request.ip_chain.geographical_context`) and time of the deletion attempt. If these match the actor’s normal behavior, it might be a false positive.
* Verify the actor’s administrative rights to ensure they are correctly configured.

**Response and remediation:**

* If unauthorized policy rule deletion is confirmed, initiate the incident response process.
* Immediately lock the affected actor account and require a password change.
* Consider resetting MFA tokens for the actor and require re-enrollment.
* Check if the compromised account was used to access or alter any sensitive data or systems.
* If a specific deletion technique was used, ensure your systems are patched or configured to prevent such techniques.
* Assess the criticality of affected services and servers.
* Work with your IT team to minimize the impact on users and maintain business continuity.
* If multiple accounts are affected, consider a broader reset or audit of MFA tokens.
* Implement security best practices [outlined](https://www.okta.com/blog/2019/10/9-admin-best-practices-to-keep-your-org-secure/) by Okta.
* Using the incident response data, update logging and audit policies to improve the mean time to detect (MTTD) and the mean time to respond (MTTR).


## Setup [_setup_1121]

The Okta Fleet integration, Filebeat module, or similarly structured data is required to be compatible with this rule.


## Rule query [_rule_query_5261]

```js
event.dataset:okta.system and event.action:policy.rule.delete
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



